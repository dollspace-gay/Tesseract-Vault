// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
// Native GUI for Tesseract using egui
// Matches the exact design from mockup

#![windows_subsystem = "windows"]

mod tray;

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;
use tesseract_lib::{
    crypto::{aes_gcm::AesGcmEncryptor, kdf::Argon2Kdf, KeyDerivation},
    validation::validate_password,
    ChunkedDecryptor, ChunkedEncryptor, ChunkedReader, StreamConfig,
};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

fn main() -> eframe::Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    let mut initial_file: Option<String> = None;
    let mut initial_mode: Option<Mode> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--encrypt" => {
                initial_mode = Some(Mode::Encrypt);
                if i + 1 < args.len() {
                    initial_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--decrypt" => {
                initial_mode = Some(Mode::Decrypt);
                if i + 1 < args.len() {
                    initial_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            arg => {
                // If it's a file path without a flag, assume it's a file to open
                if !arg.starts_with("--") {
                    initial_file = Some(arg.to_string());
                }
            }
        }
        i += 1;
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_resizable(true)
            .with_min_inner_size([900.0, 700.0])
            .with_title("Tesseract"),
        ..Default::default()
    };

    eframe::run_native(
        "Tesseract",
        options,
        Box::new(move |cc| {
            // Set custom theme with rounded corners
            let mut style = (*cc.egui_ctx.style()).clone();
            style.visuals.widgets.inactive.rounding = egui::Rounding::same(20.0);
            style.visuals.widgets.hovered.rounding = egui::Rounding::same(20.0);
            style.visuals.widgets.active.rounding = egui::Rounding::same(20.0);
            cc.egui_ctx.set_style(style);

            Ok(Box::new(CryptorApp::new(initial_file, initial_mode)))
        }),
    )
}

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    default_compression: bool,
    last_input_directory: Option<String>,
    last_output_directory: Option<String>,
    panel_transparency: u8,
    enable_notifications: bool,
    // YubiKey/HSM settings
    #[serde(default)]
    yubikey_enabled: bool,
    #[serde(default = "default_yubikey_slot")]
    yubikey_slot: u8,
}

fn default_yubikey_slot() -> u8 {
    2
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_compression: false,
            last_input_directory: None,
            last_output_directory: None,
            panel_transparency: 100,
            enable_notifications: true,
            yubikey_enabled: false,
            yubikey_slot: 2,
        }
    }
}

impl Settings {
    fn load() -> Self {
        let config_path = Self::config_path();
        if let Ok(contents) = fs::read_to_string(&config_path) {
            serde_json::from_str(&contents).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    fn save(&self) -> std::io::Result<()> {
        let config_path = Self::config_path();
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(&config_path, contents)
    }

    fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Tesseract")
            .join("settings.json")
    }
}

// Notification helper functions (cross-platform)
fn show_notification(title: &str, message: &str, _is_error: bool) {
    use notify_rust::Notification;
    let _ = Notification::new()
        .summary(title)
        .body(message)
        .appname("Tesseract")
        .show();
}

fn notify_success(operation: &str, filename: &str, enabled: bool) {
    if !enabled {
        return;
    }
    show_notification(
        "Tesseract",
        &format!("{} completed: {}", operation, filename),
        false,
    );
}

fn notify_error(operation: &str, error: &str, enabled: bool) {
    if !enabled {
        return;
    }
    show_notification(
        "Tesseract - Error",
        &format!("{} failed: {}", operation, error),
        true,
    );
}

fn notify_queue_complete(total: usize, succeeded: usize, failed: usize, enabled: bool) {
    if !enabled {
        return;
    }
    let message = if failed == 0 {
        format!(
            "Queue processing complete! {} items processed successfully.",
            succeeded
        )
    } else {
        format!(
            "Queue processing complete! {} succeeded, {} failed out of {} total.",
            succeeded, failed, total
        )
    };
    show_notification("Tesseract - Queue Complete", &message, failed > 0);
}

#[derive(PartialEq, Clone)]
enum Mode {
    Encrypt,
    Decrypt,
    Volume,
}

#[derive(PartialEq, Clone)]
enum VolumeTab {
    Create,
    Mount,
    Hidden,
    Info,
    Password,
    Security,
    RemoteWipe,
}

#[derive(Clone)]
enum QueueStatus {
    Pending,
    Processing,
    Completed,
    Failed(String),
}

#[derive(Clone)]
struct QueueItem {
    input_path: String,
    output_path: String,
    mode: Mode,
    password: String,
    use_compression: bool,
    status: QueueStatus,
    progress: f32,
}

impl QueueItem {
    fn new(
        input_path: String,
        output_path: String,
        mode: Mode,
        password: String,
        use_compression: bool,
    ) -> Self {
        Self {
            input_path,
            output_path,
            mode,
            password,
            use_compression,
            status: QueueStatus::Pending,
            progress: 0.0,
        }
    }
}

struct CryptorApp {
    mode: Option<Mode>,
    input_path: String,
    output_path: String,
    password: String,
    confirm_password: String,
    use_compression: bool,
    status_message: String,
    is_processing: bool,
    progress: f32,
    runtime: Option<Runtime>,
    settings: Settings,
    show_settings: bool,
    queue: Vec<QueueItem>,
    is_processing_queue: bool,
    show_queue_panel: bool,
    tray_manager: Option<tray::TrayManager>,
    window_visible: bool,
    // Volume management fields
    #[cfg(feature = "encrypted-volumes")]
    volume_manager: Option<tesseract_lib::volume::VolumeManager>,
    volume_tab: VolumeTab,
    volume_container_path: String,
    volume_mount_point: String,
    volume_size: String,
    volume_password: String,
    volume_password_confirm: String,
    volume_read_only: bool,
    volume_status: String,
    mounted_volumes: Vec<tesseract_lib::volume::MountedVolumeInfo>,
    volume_info: Option<String>,
    // Duress password fields
    enable_duress_password: bool,
    duress_password: String,
    duress_password_confirm: String,
    duress_status: String,
    has_duress_password: bool,
    // Remote wipe fields
    remote_wipe_enabled: bool,
    remote_wipe_token: String,
    remote_wipe_token_display: String,
    remote_wipe_status: String,
    remote_wipe_keyfile_paths: Vec<String>,
    remote_wipe_new_path: String,
    remote_wipe_require_confirmation: bool,
    remote_wipe_qr_texture: Option<egui::TextureHandle>,
    remote_wipe_show_qr: bool,
    // Hidden volume fields
    hidden_volume_container: String,
    hidden_volume_size: String,
    hidden_volume_offset: String,
    hidden_volume_password: String,
    hidden_volume_password_confirm: String,
    hidden_volume_status: String,
    mount_as_hidden: bool,
    mount_hidden_password: String,
    mount_hidden_offset: String,
    // PQC Keyfile fields for quantum-resistant encryption
    keyfile_path: String,
    keyfile_password: String,
    show_keyfile_generator: bool,
    keyfile_output_path: String,
    keyfile_protect_with_password: bool,
    keyfile_gen_password: String,
    keyfile_gen_password_confirm: String,
    keyfile_gen_status: String,
}

impl Default for CryptorApp {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl CryptorApp {
    /// Create a new CryptorApp with optional initial file and mode
    fn new(initial_file: Option<String>, initial_mode: Option<Mode>) -> Self {
        let settings = Settings::load();

        // Initialize system tray
        let tray_manager = match tray::TrayManager::new() {
            Ok(tray) => {
                eprintln!("System tray initialized successfully");
                Some(tray)
            }
            Err(e) => {
                eprintln!(
                    "Failed to initialize system tray: {}. Running without tray icon.",
                    e
                );
                None
            }
        };

        let mut app = Self {
            mode: None,
            input_path: String::new(),
            output_path: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            use_compression: settings.default_compression,
            status_message: String::new(),
            is_processing: false,
            progress: 0.0,
            runtime: None,
            settings: settings.clone(),
            show_settings: false,
            queue: Vec::new(),
            is_processing_queue: false,
            show_queue_panel: false,
            tray_manager,
            window_visible: true,
            // Volume management fields
            #[cfg(feature = "encrypted-volumes")]
            volume_manager: Some(tesseract_lib::volume::VolumeManager::new()),
            volume_tab: VolumeTab::Create,
            volume_container_path: String::new(),
            volume_mount_point: String::new(),
            volume_size: String::from("100M"),
            volume_password: String::new(),
            volume_password_confirm: String::new(),
            volume_read_only: false,
            volume_status: String::new(),
            mounted_volumes: Vec::new(),
            volume_info: None,
            // Duress password fields
            enable_duress_password: false,
            duress_password: String::new(),
            duress_password_confirm: String::new(),
            duress_status: String::new(),
            has_duress_password: false,
            // Remote wipe fields
            remote_wipe_enabled: false,
            remote_wipe_token: String::new(),
            remote_wipe_token_display: String::new(),
            remote_wipe_status: String::new(),
            remote_wipe_keyfile_paths: Vec::new(),
            remote_wipe_new_path: String::new(),
            remote_wipe_require_confirmation: true,
            remote_wipe_qr_texture: None,
            remote_wipe_show_qr: true,
            // Hidden volume fields
            hidden_volume_container: String::new(),
            hidden_volume_size: String::from("50M"),
            hidden_volume_offset: String::new(),
            hidden_volume_password: String::new(),
            hidden_volume_password_confirm: String::new(),
            hidden_volume_status: String::new(),
            mount_as_hidden: false,
            mount_hidden_password: String::new(),
            mount_hidden_offset: String::new(),
            // PQC Keyfile fields
            keyfile_path: String::new(),
            keyfile_password: String::new(),
            show_keyfile_generator: false,
            keyfile_output_path: String::new(),
            keyfile_protect_with_password: true,
            keyfile_gen_password: String::new(),
            keyfile_gen_password_confirm: String::new(),
            keyfile_gen_status: String::new(),
        };

        // If initial file is provided, set it up
        if let Some(file_path) = initial_file {
            app.input_path = file_path.clone();

            // Auto-detect mode if not explicitly provided
            let detected_mode = if file_path.ends_with(".enc") || file_path.ends_with(".encrypted")
            {
                Mode::Decrypt
            } else {
                Mode::Encrypt
            };

            // Use provided mode or detected mode
            app.mode = Some(initial_mode.unwrap_or(detected_mode));

            // Set output path based on mode
            match &app.mode {
                Some(Mode::Encrypt) => {
                    app.output_path = format!("{}.enc", file_path);
                    app.status_message = format!("Ready to encrypt: {}", file_path);
                }
                Some(Mode::Decrypt) => {
                    app.output_path = file_path
                        .trim_end_matches(".enc")
                        .trim_end_matches(".encrypted")
                        .to_string();
                    app.status_message = format!("Ready to decrypt: {}", file_path);
                }
                Some(Mode::Volume) => {
                    app.status_message = "Volume mode selected".to_string();
                }
                None => {}
            }
        }

        app
    }

    fn select_input_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.input_path = path.display().to_string();

            // Auto-detect mode based on file
            if self.input_path.ends_with(".enc") || self.input_path.ends_with(".encrypted") {
                self.mode = Some(Mode::Decrypt);
                self.output_path = self
                    .input_path
                    .trim_end_matches(".enc")
                    .trim_end_matches(".encrypted")
                    .to_string();
                self.status_message =
                    "Encrypted file detected - switched to Decrypt mode".to_string();
            } else {
                self.mode = Some(Mode::Encrypt);
                self.output_path = format!("{}.enc", self.input_path);
                self.status_message = format!("Selected: {}", path.display());
            }
        }
    }

    fn select_output_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name(&self.output_path)
            .save_file()
        {
            self.output_path = path.display().to_string();
            self.status_message = format!("Output: {}", path.display());
        }
    }

    fn add_to_queue(&mut self) {
        // Validation
        if self.input_path.is_empty() {
            self.status_message = "Error: No input file selected".to_string();
            return;
        }

        if self.output_path.is_empty() {
            self.status_message = "Error: No output file specified".to_string();
            return;
        }

        if self.password.is_empty() {
            self.status_message = "Error: Password required".to_string();
            return;
        }

        if let Some(Mode::Encrypt) = self.mode {
            if self.password != self.confirm_password {
                self.status_message = "Error: Passwords do not match".to_string();
                return;
            }

            if let Err(e) = validate_password(&self.password) {
                self.status_message = format!("Error: {}", e);
                return;
            }
        }

        // Add to queue
        let item = QueueItem::new(
            self.input_path.clone(),
            self.output_path.clone(),
            self.mode.clone().unwrap(),
            self.password.clone(),
            self.use_compression,
        );

        self.queue.push(item);
        self.status_message = format!("Added to queue: {}", self.input_path);
        self.show_queue_panel = true;

        // Clear fields for next file
        self.input_path.clear();
        self.output_path.clear();
        self.password.clear();
        self.confirm_password.clear();
    }

    fn process_queue(&mut self) {
        if self.queue.is_empty() {
            self.status_message = "Queue is empty".to_string();
            return;
        }

        self.is_processing_queue = true;

        // Get or create runtime
        let rt = self.runtime.get_or_insert_with(|| {
            tokio::runtime::Runtime::new().expect("Failed to create runtime")
        });

        let mut succeeded = 0;
        let mut failed = 0;
        let total = self.queue.len();

        // Process each item in the queue
        for item in &mut self.queue {
            if matches!(item.status, QueueStatus::Completed) {
                succeeded += 1;
                continue;
            }

            item.status = QueueStatus::Processing;
            item.progress = 0.0;

            let yubikey_enabled = self.settings.yubikey_enabled;
            let yubikey_slot = self.settings.yubikey_slot;

            let result = match item.mode {
                Mode::Encrypt => rt.block_on(async {
                    encrypt_file(
                        &item.input_path,
                        &item.output_path,
                        &item.password,
                        item.use_compression,
                        yubikey_enabled,
                        yubikey_slot,
                    )
                }),
                Mode::Decrypt => rt.block_on(async {
                    decrypt_file(
                        &item.input_path,
                        &item.output_path,
                        &item.password,
                        yubikey_enabled,
                        yubikey_slot,
                    )
                }),
                Mode::Volume => {
                    // Volume operations don't go through the queue
                    continue;
                }
            };

            match result {
                Ok(_) => {
                    item.status = QueueStatus::Completed;
                    item.progress = 1.0;
                    succeeded += 1;
                }
                Err(e) => {
                    item.status = QueueStatus::Failed(e.to_string());
                    item.progress = 0.0;
                    failed += 1;
                }
            }
        }

        self.is_processing_queue = false;
        self.status_message = "Queue processing complete".to_string();

        // Show completion notification
        notify_queue_complete(total, succeeded, failed, self.settings.enable_notifications);
    }

    fn clear_queue(&mut self) {
        self.queue.clear();
        self.status_message = "Queue cleared".to_string();
    }

    fn remove_from_queue(&mut self, index: usize) {
        if index < self.queue.len() {
            self.queue.remove(index);
            self.status_message = "Item removed from queue".to_string();
        }
    }

    fn render_queue_panel(&mut self, ctx: &egui::Context) {
        egui::Window::new("Batch Queue")
            .fixed_size([700.0, 500.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                let panel_frame = egui::Frame::default()
                    .fill(egui::Color32::from_rgba_unmultiplied(
                        255,
                        255,
                        255,
                        self.settings.panel_transparency,
                    ))
                    .rounding(egui::Rounding::same(15.0))
                    .inner_margin(egui::Margin::same(20.0));

                panel_frame.show(ui, |ui| {
                    ui.heading(
                        egui::RichText::new("Batch Operations Queue")
                            .size(24.0)
                            .color(egui::Color32::from_rgb(50, 50, 50)),
                    );

                    ui.add_space(15.0);

                    ui.label(
                        egui::RichText::new(format!("Items in queue: {}", self.queue.len()))
                            .size(14.0)
                            .color(egui::Color32::from_rgb(80, 80, 80)),
                    );

                    ui.add_space(10.0);

                    // Queue items list
                    egui::ScrollArea::vertical()
                        .max_height(300.0)
                        .show(ui, |ui| {
                            let mut items_to_remove = Vec::new();

                            for (index, item) in self.queue.iter().enumerate() {
                                ui.group(|ui| {
                                    ui.set_min_width(640.0);

                                    ui.horizontal(|ui| {
                                        // Status icon
                                        let (status_icon, status_color) = match &item.status {
                                            QueueStatus::Pending => {
                                                ("⏳", egui::Color32::from_rgb(200, 200, 200))
                                            }
                                            QueueStatus::Processing => {
                                                ("⚙", egui::Color32::from_rgb(91, 206, 250))
                                            }
                                            QueueStatus::Completed => {
                                                ("✓", egui::Color32::from_rgb(100, 200, 100))
                                            }
                                            QueueStatus::Failed(_) => {
                                                ("✗", egui::Color32::from_rgb(255, 100, 100))
                                            }
                                        };

                                        ui.label(
                                            egui::RichText::new(status_icon)
                                                .size(18.0)
                                                .color(status_color),
                                        );

                                        ui.vertical(|ui| {
                                            // File path
                                            let filename = std::path::Path::new(&item.input_path)
                                                .file_name()
                                                .and_then(|n| n.to_str())
                                                .unwrap_or(&item.input_path);

                                            ui.label(
                                                egui::RichText::new(filename)
                                                    .size(14.0)
                                                    .color(egui::Color32::from_rgb(50, 50, 50)),
                                            );

                                            // Mode indicator
                                            let mode_text = match item.mode {
                                                Mode::Encrypt => "Encrypt",
                                                Mode::Decrypt => "Decrypt",
                                                Mode::Volume => "Volume",
                                            };
                                            ui.label(
                                                egui::RichText::new(mode_text)
                                                    .size(11.0)
                                                    .color(egui::Color32::from_rgb(120, 120, 120)),
                                            );

                                            // Error message if failed
                                            if let QueueStatus::Failed(err) = &item.status {
                                                ui.label(
                                                    egui::RichText::new(format!("Error: {}", err))
                                                        .size(11.0)
                                                        .color(egui::Color32::from_rgb(
                                                            255, 100, 100,
                                                        )),
                                                );
                                            }
                                        });

                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                // Remove button
                                                if !matches!(item.status, QueueStatus::Processing) {
                                                    let remove_btn = egui::Button::new(
                                                        egui::RichText::new("✗")
                                                            .size(14.0)
                                                            .color(egui::Color32::WHITE),
                                                    )
                                                    .fill(egui::Color32::from_rgb(245, 169, 184))
                                                    .min_size(egui::vec2(30.0, 30.0))
                                                    .rounding(egui::Rounding::same(15.0));

                                                    if ui.add(remove_btn).clicked() {
                                                        items_to_remove.push(index);
                                                    }
                                                }
                                            },
                                        );
                                    });
                                });

                                ui.add_space(5.0);
                            }

                            // Remove items outside the loop
                            for index in items_to_remove.iter().rev() {
                                self.remove_from_queue(*index);
                            }
                        });

                    ui.add_space(15.0);

                    // Action buttons
                    ui.horizontal(|ui| {
                        let process_btn = egui::Button::new(
                            egui::RichText::new("⚙ Process Queue")
                                .size(16.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(91, 206, 250))
                        .min_size(egui::vec2(180.0, 40.0))
                        .rounding(egui::Rounding::same(20.0));

                        if ui
                            .add_enabled(
                                !self.is_processing_queue && !self.queue.is_empty(),
                                process_btn,
                            )
                            .clicked()
                        {
                            self.process_queue();
                        }

                        ui.add_space(10.0);

                        let clear_btn = egui::Button::new(
                            egui::RichText::new("Clear Queue")
                                .size(16.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(245, 169, 184))
                        .min_size(egui::vec2(150.0, 40.0))
                        .rounding(egui::Rounding::same(20.0));

                        if ui
                            .add_enabled(!self.is_processing_queue, clear_btn)
                            .clicked()
                        {
                            self.clear_queue();
                        }

                        ui.add_space(10.0);

                        let close_btn = egui::Button::new(
                            egui::RichText::new("Close")
                                .size(16.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(120, 120, 120))
                        .min_size(egui::vec2(100.0, 40.0))
                        .rounding(egui::Rounding::same(20.0));

                        if ui.add(close_btn).clicked() {
                            self.show_queue_panel = false;
                        }
                    });

                    if self.is_processing_queue {
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new("Processing queue...")
                                .size(13.0)
                                .color(egui::Color32::from_rgb(91, 206, 250)),
                        );
                    }
                });
            });
    }

    fn render_settings_panel(&mut self, ctx: &egui::Context) {
        egui::Window::new("Settings")
            .fixed_size([500.0, 400.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                // Apply trans pride theme to settings panel
                let panel_frame = egui::Frame::default()
                    .fill(egui::Color32::from_rgba_unmultiplied(255, 255, 255, self.settings.panel_transparency))
                    .rounding(egui::Rounding::same(15.0))
                    .inner_margin(egui::Margin::same(25.0))
                    .shadow(egui::epaint::Shadow {
                        offset: egui::Vec2::new(0.0, 4.0),
                        blur: 15.0,
                        spread: 0.0,
                        color: egui::Color32::from_black_alpha(40),
                    });

                panel_frame.show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("⚙ Settings")
                            .size(28.0)
                            .color(egui::Color32::from_rgb(50, 50, 50)));
                    });

                    ui.add_space(20.0);

                    // Default compression checkbox
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Default Compression:").size(14.0));
                        ui.add_space(10.0);
                        if ui.checkbox(&mut self.settings.default_compression, "").changed() {
                            self.use_compression = self.settings.default_compression;
                            let _ = self.settings.save();
                        }
                    });

                    ui.add_space(15.0);

                    // Enable notifications checkbox
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Enable Notifications:").size(14.0));
                        ui.add_space(10.0);
                        if ui.checkbox(&mut self.settings.enable_notifications, "").changed() {
                            let _ = self.settings.save();
                        }
                    });

                    ui.add_space(15.0);

                    // YubiKey settings section
                    ui.separator();
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("Hardware Security (YubiKey)")
                        .size(16.0)
                        .color(egui::Color32::from_rgb(50, 50, 50)));
                    ui.add_space(10.0);

                    // YubiKey enabled checkbox
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Enable YubiKey 2FA:").size(14.0));
                        ui.add_space(10.0);
                        if ui.checkbox(&mut self.settings.yubikey_enabled, "").changed() {
                            let _ = self.settings.save();
                        }
                    });

                    // YubiKey slot selector (only show if YubiKey is enabled)
                    if self.settings.yubikey_enabled {
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("YubiKey Slot:").size(14.0));
                            ui.add_space(10.0);

                            let slot1_selected = self.settings.yubikey_slot == 1;
                            let slot2_selected = self.settings.yubikey_slot == 2;

                            if ui.selectable_label(slot1_selected, "Slot 1").clicked() {
                                self.settings.yubikey_slot = 1;
                                let _ = self.settings.save();
                            }
                            ui.add_space(5.0);
                            if ui.selectable_label(slot2_selected, "Slot 2").clicked() {
                                self.settings.yubikey_slot = 2;
                                let _ = self.settings.save();
                            }
                        });

                        ui.add_space(5.0);
                        ui.label(egui::RichText::new("Note: YubiKey must be configured with HMAC-SHA1 challenge-response")
                            .size(11.0)
                            .color(egui::Color32::from_rgb(120, 120, 120)));
                    }

                    ui.add_space(15.0);
                    ui.separator();
                    ui.add_space(10.0);

                    // Panel transparency slider
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Panel Transparency:").size(14.0));
                        ui.add_space(10.0);
                    });

                    ui.add_space(5.0);

                    ui.horizontal(|ui| {
                        let slider = egui::Slider::new(&mut self.settings.panel_transparency, 50..=255)
                            .text("Alpha")
                            .show_value(true);
                        if ui.add(slider).changed() {
                            let _ = self.settings.save();
                        }
                    });

                    ui.add_space(20.0);

                    // Settings info
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("Settings are automatically saved")
                            .size(11.0)
                            .color(egui::Color32::from_rgb(100, 100, 100)));

                        ui.add_space(10.0);

                        let config_path = Settings::config_path();
                        ui.label(egui::RichText::new(format!("Location: {}", config_path.display()))
                            .size(10.0)
                            .color(egui::Color32::from_rgb(120, 120, 120)));
                    });

                    ui.add_space(20.0);

                    // Close button
                    ui.vertical_centered(|ui| {
                        let close_btn = egui::Button::new(
                            egui::RichText::new("Close").size(16.0).color(egui::Color32::WHITE)
                        )
                        .fill(egui::Color32::from_rgb(91, 206, 250))
                        .min_size(egui::vec2(150.0, 40.0))
                        .rounding(egui::Rounding::same(20.0));

                        if ui.add(close_btn).clicked() {
                            self.show_settings = false;
                        }
                    });
                });
            });
    }

    #[cfg(feature = "post-quantum")]
    fn render_keyfile_generator(&mut self, ctx: &egui::Context) {
        egui::Window::new("Generate PQC Keyfile")
            .fixed_size([550.0, 450.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                let panel_frame = egui::Frame::default()
                    .fill(egui::Color32::from_rgba_unmultiplied(255, 255, 255, self.settings.panel_transparency))
                    .rounding(egui::Rounding::same(15.0))
                    .inner_margin(egui::Margin::same(25.0))
                    .shadow(egui::epaint::Shadow {
                        offset: egui::Vec2::new(0.0, 4.0),
                        blur: 15.0,
                        spread: 0.0,
                        color: egui::Color32::from_black_alpha(40),
                    });

                panel_frame.show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("🔐 Generate Quantum-Resistant Keyfile")
                            .size(22.0)
                            .color(egui::Color32::from_rgb(50, 50, 50)));
                    });

                    ui.add_space(15.0);

                    ui.label(egui::RichText::new(
                        "Generate a new ML-KEM-1024 keyfile for quantum-resistant encryption.\n\
                        This keyfile will be required when encrypting and decrypting files."
                    ).size(12.0).color(egui::Color32::from_rgb(80, 80, 80)));

                    ui.add_space(20.0);

                    // Output path selection
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Save Location:").size(14.0));
                        ui.add_space(10.0);
                        let text_edit = egui::TextEdit::singleline(&mut self.keyfile_output_path)
                            .desired_width(300.0)
                            .hint_text("Choose keyfile location (.tkf)");
                        ui.add(text_edit);
                        ui.add_space(5.0);

                        let browse_btn = egui::Button::new("Browse")
                            .min_size(egui::vec2(70.0, 30.0))
                            .fill(egui::Color32::from_rgb(200, 200, 200));

                        if ui.add(browse_btn).clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Tesseract Keyfile", &["tkf"])
                                .set_file_name("keyfile.tkf")
                                .save_file()
                            {
                                self.keyfile_output_path = path.display().to_string();
                            }
                        }
                    });

                    ui.add_space(15.0);

                    // Password protection checkbox
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Password Protect Keyfile:").size(14.0));
                        ui.add_space(10.0);
                        ui.checkbox(&mut self.keyfile_protect_with_password, "");
                    });

                    // Password fields (only show if password protection enabled)
                    if self.keyfile_protect_with_password {
                        ui.add_space(10.0);

                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Password:").size(14.0));
                            ui.add_space(10.0);
                            let password_edit = egui::TextEdit::singleline(&mut self.keyfile_gen_password)
                                .desired_width(300.0)
                                .password(true);
                            ui.add(password_edit);
                        });

                        ui.add_space(8.0);

                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Confirm:").size(14.0));
                            ui.add_space(10.0);
                            let confirm_edit = egui::TextEdit::singleline(&mut self.keyfile_gen_password_confirm)
                                .desired_width(300.0)
                                .password(true);
                            ui.add(confirm_edit);
                        });
                    }

                    ui.add_space(20.0);

                    // Status message
                    if !self.keyfile_gen_status.is_empty() {
                        let status_color = if self.keyfile_gen_status.starts_with("Error") {
                            egui::Color32::from_rgb(200, 50, 50)
                        } else {
                            egui::Color32::from_rgb(50, 150, 50)
                        };
                        ui.label(egui::RichText::new(&self.keyfile_gen_status)
                            .size(13.0)
                            .color(status_color));
                        ui.add_space(10.0);
                    }

                    ui.add_space(10.0);

                    // Buttons
                    ui.horizontal(|ui| {
                        ui.add_space(100.0);

                        // Generate button
                        let can_generate = !self.keyfile_output_path.is_empty()
                            && (!self.keyfile_protect_with_password
                                || (!self.keyfile_gen_password.is_empty()
                                    && self.keyfile_gen_password == self.keyfile_gen_password_confirm));

                        let generate_btn = egui::Button::new(
                            egui::RichText::new("Generate Keyfile").size(16.0).color(egui::Color32::WHITE)
                        )
                        .fill(if can_generate {
                            egui::Color32::from_rgb(91, 206, 250)
                        } else {
                            egui::Color32::from_rgb(180, 180, 180)
                        })
                        .min_size(egui::vec2(150.0, 40.0))
                        .rounding(egui::Rounding::same(20.0));

                        if ui.add_enabled(can_generate, generate_btn).clicked() {
                            self.generate_keyfile();
                        }

                        ui.add_space(20.0);

                        // Cancel button
                        let cancel_btn = egui::Button::new(
                            egui::RichText::new("Cancel").size(16.0)
                        )
                        .min_size(egui::vec2(100.0, 40.0))
                        .rounding(egui::Rounding::same(20.0));

                        if ui.add(cancel_btn).clicked() {
                            self.show_keyfile_generator = false;
                            self.keyfile_gen_status.clear();
                            self.keyfile_gen_password.clear();
                            self.keyfile_gen_password_confirm.clear();
                        }
                    });

                    ui.add_space(15.0);

                    // Info note
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("⚠ Keep your keyfile secure! Without it, encrypted files cannot be decrypted.")
                            .size(11.0)
                            .color(egui::Color32::from_rgb(150, 100, 50)));
                    });
                });
            });
    }

    #[cfg(feature = "post-quantum")]
    fn generate_keyfile(&mut self) {
        use std::path::Path;
        use tesseract_lib::crypto::keyfile::PqcKeyfile;

        let output_path = Path::new(&self.keyfile_output_path);

        // Ensure .tkf extension
        let output_path = if output_path.extension().is_some_and(|e| e == "tkf") {
            output_path.to_path_buf()
        } else {
            output_path.with_extension("tkf")
        };

        // Generate the keyfile
        let keyfile = PqcKeyfile::generate();

        // Save with or without password protection
        let save_result = if self.keyfile_protect_with_password {
            keyfile.save_protected(&output_path, &self.keyfile_gen_password)
        } else {
            keyfile.save_unprotected(&output_path)
        };

        match save_result {
            Ok(()) => {
                self.keyfile_gen_status = format!("✓ Keyfile generated: {}", output_path.display());
                // Set the generated keyfile as the active keyfile
                self.keyfile_path = output_path.display().to_string();
                if self.keyfile_protect_with_password {
                    self.keyfile_password = self.keyfile_gen_password.clone();
                }
                // Close the window after a successful generation
                self.show_keyfile_generator = false;
                self.keyfile_gen_password.clear();
                self.keyfile_gen_password_confirm.clear();
            }
            Err(e) => {
                self.keyfile_gen_status = format!("Error saving keyfile: {}", e);
            }
        }
    }

    fn process_file(&mut self) {
        // Validation
        if self.input_path.is_empty() {
            self.status_message = "Error: No input file selected".to_string();
            return;
        }

        if self.output_path.is_empty() {
            self.status_message = "Error: No output file specified".to_string();
            return;
        }

        if self.password.is_empty() {
            self.status_message = "Error: Password required".to_string();
            return;
        }

        if let Some(Mode::Encrypt) = self.mode {
            if self.password != self.confirm_password {
                self.status_message = "Error: Passwords do not match".to_string();
                return;
            }

            if let Err(e) = validate_password(&self.password) {
                self.status_message = format!("Error: {}", e);
                return;
            }
        }

        // Get or create runtime
        let rt = self.runtime.get_or_insert_with(|| {
            tokio::runtime::Runtime::new().expect("Failed to create runtime")
        });

        let input_path = self.input_path.clone();
        let output_path = self.output_path.clone();
        let password = self.password.clone();
        let use_compression = self.use_compression;
        let mode = self.mode.as_ref().unwrap();

        self.is_processing = true;
        self.progress = 0.0;

        // YubiKey settings (only used when post-quantum is disabled)
        #[cfg(not(feature = "post-quantum"))]
        let yubikey_enabled = self.settings.yubikey_enabled;
        #[cfg(not(feature = "post-quantum"))]
        let yubikey_slot = self.settings.yubikey_slot;

        // Get keyfile info for PQC encryption
        #[cfg(feature = "post-quantum")]
        let keyfile_path = self.keyfile_path.clone();
        #[cfg(feature = "post-quantum")]
        let keyfile_password = if self.keyfile_password.is_empty() {
            None
        } else {
            Some(self.keyfile_password.clone())
        };

        match mode {
            Mode::Encrypt => {
                // Keyfile is REQUIRED for encryption when post-quantum feature is enabled
                #[cfg(feature = "post-quantum")]
                let result: Result<String, Box<dyn std::error::Error>> = if keyfile_path.is_empty()
                {
                    Err("Keyfile is required for encryption. Generate or select a .tkf keyfile first.".into())
                } else {
                    rt.block_on(async {
                        encrypt_file_with_keyfile(
                            &input_path,
                            &output_path,
                            &password,
                            &keyfile_path,
                            keyfile_password.as_deref(),
                            use_compression,
                        )
                    })
                };

                #[cfg(not(feature = "post-quantum"))]
                let result = rt.block_on(async {
                    encrypt_file(
                        &input_path,
                        &output_path,
                        &password,
                        use_compression,
                        yubikey_enabled,
                        yubikey_slot,
                    )
                });

                match result {
                    Ok(msg) => {
                        self.status_message = msg;
                        self.progress = 1.0;

                        // Show success notification
                        let filename = std::path::Path::new(&output_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(&output_path);
                        notify_success("Encryption", filename, self.settings.enable_notifications);
                    }
                    Err(e) => {
                        self.status_message = format!("Encryption failed: {}", e);
                        self.progress = 0.0;

                        // Show error notification
                        notify_error(
                            "Encryption",
                            &e.to_string(),
                            self.settings.enable_notifications,
                        );
                    }
                }
            }
            Mode::Decrypt => {
                // Keyfile is REQUIRED for decryption of PQC-encrypted files
                #[cfg(feature = "post-quantum")]
                let result: Result<String, Box<dyn std::error::Error>> = if keyfile_path.is_empty()
                {
                    Err("Keyfile is required for decryption. Select the .tkf keyfile used during encryption.".into())
                } else {
                    rt.block_on(async {
                        decrypt_file_with_keyfile(
                            &input_path,
                            &output_path,
                            &password,
                            &keyfile_path,
                            keyfile_password.as_deref(),
                        )
                    })
                };

                #[cfg(not(feature = "post-quantum"))]
                let result = rt.block_on(async {
                    decrypt_file(
                        &input_path,
                        &output_path,
                        &password,
                        yubikey_enabled,
                        yubikey_slot,
                    )
                });

                match result {
                    Ok(msg) => {
                        self.status_message = msg;
                        self.progress = 1.0;

                        // Show success notification
                        let filename = std::path::Path::new(&output_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(&output_path);
                        notify_success("Decryption", filename, self.settings.enable_notifications);
                    }
                    Err(e) => {
                        self.status_message = format!("Decryption failed: {}", e);
                        self.progress = 0.0;

                        // Show error notification
                        notify_error(
                            "Decryption",
                            &e.to_string(),
                            self.settings.enable_notifications,
                        );
                    }
                }
            }
            Mode::Volume => {
                // Volume operations are handled separately, not through this process_file method
                self.status_message = "Volume operations available via Volumes menu".to_string();
                self.progress = 0.0;
            }
        }

        self.is_processing = false;
    }

    #[cfg(feature = "encrypted-volumes")]
    fn render_volume_ui(&mut self, ui: &mut egui::Ui) {
        use tesseract_lib::volume::Container;

        // Tab buttons
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new("Volume Operations").size(20.0));
            ui.add_space(15.0);

            ui.horizontal(|ui| {
                ui.allocate_space(egui::vec2(100.0, 0.0));

                let create_color = if self.volume_tab == VolumeTab::Create {
                    egui::Color32::from_rgb(91, 206, 250)
                } else {
                    egui::Color32::from_rgb(200, 200, 200)
                };

                let mount_color = if self.volume_tab == VolumeTab::Mount {
                    egui::Color32::from_rgb(91, 206, 250)
                } else {
                    egui::Color32::from_rgb(200, 200, 200)
                };

                let hidden_color = if self.volume_tab == VolumeTab::Hidden {
                    egui::Color32::from_rgb(91, 206, 250)
                } else {
                    egui::Color32::from_rgb(200, 200, 200)
                };

                let info_color = if self.volume_tab == VolumeTab::Info {
                    egui::Color32::from_rgb(91, 206, 250)
                } else {
                    egui::Color32::from_rgb(200, 200, 200)
                };

                let password_color = if self.volume_tab == VolumeTab::Password {
                    egui::Color32::from_rgb(91, 206, 250)
                } else {
                    egui::Color32::from_rgb(200, 200, 200)
                };

                let security_color = if self.volume_tab == VolumeTab::Security {
                    egui::Color32::from_rgb(91, 206, 250)
                } else {
                    egui::Color32::from_rgb(200, 200, 200)
                };

                let remote_wipe_color = if self.volume_tab == VolumeTab::RemoteWipe {
                    egui::Color32::from_rgb(91, 206, 250)
                } else {
                    egui::Color32::from_rgb(200, 200, 200)
                };

                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("📦 Create")
                                .size(14.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(create_color)
                        .min_size(egui::vec2(120.0, 40.0))
                        .rounding(egui::Rounding::same(20.0)),
                    )
                    .clicked()
                {
                    self.volume_tab = VolumeTab::Create;
                }

                ui.add_space(10.0);

                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("💾 Mount")
                                .size(14.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(mount_color)
                        .min_size(egui::vec2(120.0, 40.0))
                        .rounding(egui::Rounding::same(20.0)),
                    )
                    .clicked()
                {
                    self.volume_tab = VolumeTab::Mount;
                }

                ui.add_space(10.0);

                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("🔒 Hidden")
                                .size(14.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(hidden_color)
                        .min_size(egui::vec2(120.0, 40.0))
                        .rounding(egui::Rounding::same(20.0)),
                    )
                    .clicked()
                {
                    self.volume_tab = VolumeTab::Hidden;
                }

                ui.add_space(10.0);

                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("ℹ️ Info")
                                .size(14.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(info_color)
                        .min_size(egui::vec2(120.0, 40.0))
                        .rounding(egui::Rounding::same(20.0)),
                    )
                    .clicked()
                {
                    self.volume_tab = VolumeTab::Info;
                }

                ui.add_space(10.0);

                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("🔐 Password")
                                .size(14.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(password_color)
                        .min_size(egui::vec2(120.0, 40.0))
                        .rounding(egui::Rounding::same(20.0)),
                    )
                    .clicked()
                {
                    self.volume_tab = VolumeTab::Password;
                }

                ui.add_space(10.0);

                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("🛡️ Security")
                                .size(14.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(security_color)
                        .min_size(egui::vec2(120.0, 40.0))
                        .rounding(egui::Rounding::same(20.0)),
                    )
                    .clicked()
                {
                    self.volume_tab = VolumeTab::Security;
                }

                ui.add_space(10.0);

                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("📡 Remote Wipe")
                                .size(14.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(remote_wipe_color)
                        .min_size(egui::vec2(130.0, 40.0))
                        .rounding(egui::Rounding::same(20.0)),
                    )
                    .clicked()
                {
                    self.volume_tab = VolumeTab::RemoteWipe;
                }
            });
        });

        ui.add_space(30.0);

        // Tab content
        match self.volume_tab {
            VolumeTab::Create => {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("Create New Encrypted Volume").size(18.0));
                });
                ui.add_space(20.0);

                // Container path
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Container Path").size(14.0));
                    ui.add_space(10.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_container_path)
                            .desired_width(450.0),
                    );
                    ui.add_space(10.0);
                    if ui.button("Browse...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_file_name("volume.crypt")
                            .save_file()
                        {
                            self.volume_container_path = path.display().to_string();
                        }
                    }
                });

                ui.add_space(15.0);

                // Volume size
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Volume Size").size(14.0));
                    ui.add_space(38.0);
                    ui.add(egui::TextEdit::singleline(&mut self.volume_size).desired_width(450.0));
                    ui.add_space(10.0);
                    ui.label("(e.g., 100M, 1G, 500M)");
                });

                ui.add_space(15.0);

                // Password
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Password").size(14.0));
                    ui.add_space(58.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_password)
                            .password(true)
                            .desired_width(450.0),
                    );
                });

                ui.add_space(15.0);

                // Confirm password
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Confirm Password").size(14.0));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_password_confirm)
                            .password(true)
                            .desired_width(450.0),
                    );
                });

                ui.add_space(20.0);

                // Duress password section
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.enable_duress_password, "");
                    ui.label(
                        egui::RichText::new("Enable Duress Password (Self-Destruct)").size(14.0),
                    );
                });

                if self.enable_duress_password {
                    ui.add_space(8.0);

                    // Warning box
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(60, 30, 30))
                        .rounding(egui::Rounding::same(8.0))
                        .inner_margin(egui::Margin::same(12.0))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("⚠️ WARNING: If you enter the duress password when opening this volume, ALL encryption keys will be permanently destroyed. The volume will become unrecoverable.")
                                .size(12.0)
                                .color(egui::Color32::from_rgb(255, 180, 180)));
                        });

                    ui.add_space(10.0);

                    // Duress password
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Duress Password").size(14.0));
                        ui.add_space(22.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.duress_password)
                                .password(true)
                                .desired_width(450.0),
                        );
                    });

                    ui.add_space(10.0);

                    // Confirm duress password
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Confirm Duress").size(14.0));
                        ui.add_space(30.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.duress_password_confirm)
                                .password(true)
                                .desired_width(450.0),
                        );
                    });

                    // Validation
                    if !self.duress_password.is_empty()
                        && self.duress_password == self.volume_password
                    {
                        ui.add_space(5.0);
                        ui.label(
                            egui::RichText::new(
                                "✗ Duress password must be different from main password",
                            )
                            .size(12.0)
                            .color(egui::Color32::from_rgb(255, 100, 100)),
                        );
                    }
                }

                ui.add_space(20.0);

                // Create button
                ui.vertical_centered(|ui| {
                    // Basic validation
                    let basic_valid = !self.volume_container_path.is_empty()
                        && !self.volume_size.is_empty()
                        && !self.volume_password.is_empty()
                        && self.volume_password == self.volume_password_confirm;

                    // Duress password validation (if enabled)
                    let duress_valid = if self.enable_duress_password {
                        !self.duress_password.is_empty()
                            && self.duress_password == self.duress_password_confirm
                            && self.duress_password != self.volume_password
                    } else {
                        true
                    };

                    let can_create = basic_valid && duress_valid;

                    if ui.add_enabled(can_create, egui::Button::new(
                        egui::RichText::new("📦 Create Volume").size(16.0).color(egui::Color32::WHITE))
                        .fill(egui::Color32::from_rgb(91, 206, 250))
                        .min_size(egui::vec2(250.0, 50.0))
                        .rounding(egui::Rounding::same(25.0))).clicked() {

                        // Parse size
                        let size_result = parse_size(&self.volume_size);
                        match size_result {
                            Ok(size_bytes) => {
                                match Container::create(
                                    std::path::Path::new(&self.volume_container_path),
                                    size_bytes,
                                    &self.volume_password,
                                    4096,
                                ) {
                                    Ok(_) => {
                                        // Set duress password if enabled
                                        if self.enable_duress_password && !self.duress_password.is_empty() {
                                            // Open the container to set duress password
                                            match Container::open(
                                                std::path::Path::new(&self.volume_container_path),
                                                &self.volume_password,
                                            ) {
                                                Ok(mut container) => {
                                                    match container.set_duress_password(&self.duress_password) {
                                                        Ok(_) => {
                                                            self.volume_status = format!("✓ Volume created with duress password: {} bytes", size_bytes);
                                                        }
                                                        Err(e) => {
                                                            self.volume_status = format!("✓ Volume created but duress password failed: {}", e);
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    self.volume_status = format!("✓ Volume created but couldn't set duress password: {}", e);
                                                }
                                            }
                                        } else {
                                            self.volume_status = format!("✓ Volume created successfully: {} bytes", size_bytes);
                                        }
                                        self.volume_password.clear();
                                        self.volume_password_confirm.clear();
                                        self.duress_password.clear();
                                        self.duress_password_confirm.clear();
                                        self.enable_duress_password = false;
                                    }
                                    Err(e) => {
                                        self.volume_status = format!("✗ Error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                self.volume_status = format!("✗ Invalid size format: {}", e);
                            }
                        }
                    }
                });

                // Status message
                if !self.volume_status.is_empty() {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new(&self.volume_status).size(13.0));
                    });
                }
            }

            VolumeTab::Mount => {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("Mount/Unmount Encrypted Volume").size(18.0));
                });
                ui.add_space(20.0);

                // Container path
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Container Path").size(14.0));
                    ui.add_space(10.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_container_path)
                            .desired_width(450.0),
                    );
                    ui.add_space(10.0);
                    if ui.button("Browse...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.volume_container_path = path.display().to_string();
                        }
                    }
                });

                ui.add_space(15.0);

                // Mount point
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Mount Point").size(14.0));
                    ui.add_space(25.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_mount_point)
                            .desired_width(450.0),
                    );
                    ui.add_space(10.0);
                    if ui.button("Browse...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.volume_mount_point = path.display().to_string();
                        }
                    }
                });

                ui.add_space(15.0);

                // Password
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Password").size(14.0));
                    ui.add_space(58.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_password)
                            .password(true)
                            .desired_width(450.0),
                    );
                });

                ui.add_space(15.0);

                // Read-only checkbox
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.volume_read_only, "Mount as read-only");
                });

                ui.add_space(15.0);

                // Mount hidden volume checkbox
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.mount_as_hidden, "Mount hidden volume");
                });

                // Hidden volume fields (shown only when checkbox is checked)
                if self.mount_as_hidden {
                    ui.add_space(10.0);

                    // Hidden volume offset
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Hidden Offset").size(14.0));
                        ui.add_space(20.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.mount_hidden_offset)
                                .desired_width(420.0),
                        );
                        ui.add_space(10.0);
                        ui.label("(e.g., 500M)");
                    });

                    ui.add_space(10.0);

                    // Hidden volume password
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Hidden Password").size(14.0));
                        ui.add_space(2.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.mount_hidden_password)
                                .password(true)
                                .desired_width(420.0),
                        );
                    });
                }

                ui.add_space(30.0);

                // Mount/Unmount buttons
                ui.vertical_centered(|ui| {
                    ui.horizontal(|ui| {
                        let basic_valid = !self.volume_container_path.is_empty()
                            && !self.volume_mount_point.is_empty()
                            && !self.volume_password.is_empty();

                        let hidden_valid = if self.mount_as_hidden {
                            !self.mount_hidden_offset.is_empty()
                                && !self.mount_hidden_password.is_empty()
                        } else {
                            true
                        };

                        let can_mount = basic_valid && hidden_valid;

                        if ui
                            .add_enabled(
                                can_mount,
                                egui::Button::new(
                                    egui::RichText::new("💾 Mount Volume")
                                        .size(16.0)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(91, 206, 250))
                                .min_size(egui::vec2(200.0, 50.0))
                                .rounding(egui::Rounding::same(25.0)),
                            )
                            .clicked()
                        {
                            #[cfg(feature = "encrypted-volumes")]
                            {
                                use tesseract_lib::volume::MountOptions;

                                // Parse hidden offset if mounting hidden volume
                                let (hidden_offset, hidden_password) = if self.mount_as_hidden {
                                    match parse_size(&self.mount_hidden_offset) {
                                        Ok(offset) => {
                                            (Some(offset), Some(self.mount_hidden_password.clone()))
                                        }
                                        Err(e) => {
                                            self.volume_status =
                                                format!("✗ Invalid hidden offset: {}", e);
                                            return;
                                        }
                                    }
                                } else {
                                    (None, None)
                                };

                                if let Some(ref mut manager) = self.volume_manager {
                                    let options = MountOptions {
                                        mount_point: std::path::PathBuf::from(
                                            &self.volume_mount_point,
                                        ),
                                        read_only: self.volume_read_only,
                                        allow_other: false,
                                        auto_unmount: true,
                                        fs_name: Some("Tesseract".to_string()),
                                        hidden_offset,
                                        hidden_password,
                                    };

                                    match manager.mount(
                                        std::path::Path::new(&self.volume_container_path),
                                        &self.volume_password,
                                        options,
                                    ) {
                                        Ok(_) => {
                                            let mount_type = if self.mount_as_hidden {
                                                "Hidden volume"
                                            } else {
                                                "Volume"
                                            };
                                            self.volume_status = format!(
                                                "✓ {} mounted at {}",
                                                mount_type, self.volume_mount_point
                                            );
                                            self.volume_password.clear();
                                            self.mount_hidden_password.clear();
                                            // Update mounted volumes list
                                            self.mounted_volumes = manager.list_mounted();
                                        }
                                        Err(e) => {
                                            self.volume_status = format!("✗ Mount error: {}", e);
                                        }
                                    }
                                }
                            }
                        }

                        ui.add_space(20.0);

                        if ui
                            .add_enabled(
                                !self.volume_container_path.is_empty(),
                                egui::Button::new(
                                    egui::RichText::new("⏏️ Unmount")
                                        .size(16.0)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(245, 169, 184))
                                .min_size(egui::vec2(200.0, 50.0))
                                .rounding(egui::Rounding::same(25.0)),
                            )
                            .clicked()
                        {
                            #[cfg(feature = "encrypted-volumes")]
                            {
                                if let Some(ref mut manager) = self.volume_manager {
                                    match manager
                                        .unmount(std::path::Path::new(&self.volume_container_path))
                                    {
                                        Ok(_) => {
                                            self.volume_status =
                                                "✓ Volume unmounted successfully".to_string();
                                            // Update mounted volumes list
                                            self.mounted_volumes = manager.list_mounted();
                                        }
                                        Err(e) => {
                                            self.volume_status = format!("✗ Unmount error: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    });
                });

                // Status message
                if !self.volume_status.is_empty() {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new(&self.volume_status).size(13.0));
                    });
                }

                // Mounted volumes list
                if !self.mounted_volumes.is_empty() {
                    ui.add_space(30.0);
                    ui.separator();
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("Currently Mounted Volumes").size(16.0));
                    ui.add_space(10.0);

                    for vol_info in &self.mounted_volumes {
                        ui.horizontal(|ui| {
                            ui.label(format!(
                                "📦 {} → {}",
                                vol_info.container_path.display(),
                                vol_info.mount_point.display()
                            ));
                        });
                    }
                }
            }

            VolumeTab::Hidden => {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("Hidden Volume Management").size(18.0));
                });
                ui.add_space(10.0);

                // Info box about hidden volumes
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(40, 40, 60))
                    .rounding(egui::Rounding::same(8.0))
                    .inner_margin(egui::Margin::same(12.0))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("🔒 Hidden volumes provide plausible deniability. They are encrypted containers within your outer volume that cannot be detected without the correct password and offset.")
                            .size(12.0)
                            .color(egui::Color32::from_rgb(180, 180, 220)));
                    });

                ui.add_space(20.0);

                // Container path (outer volume)
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Outer Container").size(14.0));
                    ui.add_space(10.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.hidden_volume_container)
                            .desired_width(420.0),
                    );
                    ui.add_space(10.0);
                    if ui.button("Browse...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.hidden_volume_container = path.display().to_string();
                        }
                    }
                });

                ui.add_space(15.0);

                // Hidden volume size
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Hidden Size").size(14.0));
                    ui.add_space(32.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.hidden_volume_size)
                            .desired_width(420.0),
                    );
                    ui.add_space(10.0);
                    ui.label("(e.g., 50M, 100M)");
                });

                ui.add_space(15.0);

                // Hidden volume offset
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Offset").size(14.0));
                    ui.add_space(65.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.hidden_volume_offset)
                            .desired_width(420.0),
                    );
                    ui.add_space(10.0);
                    ui.label("(e.g., 500M from start)");
                });

                ui.add_space(15.0);

                // Outer volume password (to unlock outer container)
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Outer Password").size(14.0));
                    ui.add_space(10.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_password)
                            .password(true)
                            .desired_width(420.0),
                    );
                });

                ui.add_space(15.0);

                // Hidden volume password
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Hidden Password").size(14.0));
                    ui.add_space(2.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.hidden_volume_password)
                            .password(true)
                            .desired_width(420.0),
                    );
                });

                ui.add_space(15.0);

                // Confirm hidden password
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Confirm Hidden").size(14.0));
                    ui.add_space(12.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.hidden_volume_password_confirm)
                            .password(true)
                            .desired_width(420.0),
                    );
                });

                ui.add_space(25.0);

                // Create hidden volume button
                ui.vertical_centered(|ui| {
                    let can_create = !self.hidden_volume_container.is_empty()
                        && !self.hidden_volume_size.is_empty()
                        && !self.hidden_volume_offset.is_empty()
                        && !self.volume_password.is_empty()
                        && !self.hidden_volume_password.is_empty()
                        && self.hidden_volume_password == self.hidden_volume_password_confirm;

                    if ui
                        .add_enabled(
                            can_create,
                            egui::Button::new(
                                egui::RichText::new("🔒 Create Hidden Volume")
                                    .size(16.0)
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(egui::Color32::from_rgb(91, 206, 250))
                            .min_size(egui::vec2(250.0, 50.0))
                            .rounding(egui::Rounding::same(25.0)),
                        )
                        .clicked()
                    {
                        #[cfg(feature = "encrypted-volumes")]
                        {
                            use tesseract_lib::volume::Container;

                            // Parse sizes
                            let size_result = parse_size(&self.hidden_volume_size);
                            let offset_result = parse_size(&self.hidden_volume_offset);

                            match (size_result, offset_result) {
                                (Ok(hidden_size), Ok(hidden_offset)) => {
                                    // Open the outer container
                                    match Container::open(
                                        std::path::Path::new(&self.hidden_volume_container),
                                        &self.volume_password,
                                    ) {
                                        Ok(mut container) => {
                                            match container.create_hidden_volume(
                                                hidden_size,
                                                &self.hidden_volume_password,
                                                hidden_offset,
                                            ) {
                                                Ok(_) => {
                                                    self.hidden_volume_status = format!(
                                                        "✅ Hidden volume created: {} at offset {}",
                                                        self.hidden_volume_size,
                                                        self.hidden_volume_offset
                                                    );
                                                    // Clear passwords
                                                    self.volume_password.clear();
                                                    self.hidden_volume_password.clear();
                                                    self.hidden_volume_password_confirm.clear();
                                                }
                                                Err(e) => {
                                                    self.hidden_volume_status = format!(
                                                        "❌ Failed to create hidden volume: {}",
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            self.hidden_volume_status =
                                                format!("❌ Failed to open outer container: {}", e);
                                        }
                                    }
                                }
                                (Err(e), _) => {
                                    self.hidden_volume_status =
                                        format!("❌ Invalid hidden size: {}", e);
                                }
                                (_, Err(e)) => {
                                    self.hidden_volume_status = format!("❌ Invalid offset: {}", e);
                                }
                            }
                        }
                    }
                });

                // Status message
                if !self.hidden_volume_status.is_empty() {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new(&self.hidden_volume_status).size(14.0));
                    });
                }

                // Security warning
                ui.add_space(30.0);
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(60, 40, 30))
                    .rounding(egui::Rounding::same(8.0))
                    .inner_margin(egui::Margin::same(12.0))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("⚠️ IMPORTANT: Remember your offset! Without the correct offset and password, your hidden volume cannot be accessed. Fill the outer volume with decoy data for best plausible deniability.")
                            .size(12.0)
                            .color(egui::Color32::from_rgb(255, 200, 150)));
                    });
            }

            VolumeTab::Info => {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("Volume Information").size(18.0));
                });
                ui.add_space(20.0);

                // Container path
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Container Path").size(14.0));
                    ui.add_space(10.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_container_path)
                            .desired_width(450.0),
                    );
                    ui.add_space(10.0);
                    if ui.button("Browse...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.volume_container_path = path.display().to_string();
                        }
                    }
                });

                ui.add_space(15.0);

                // Password
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Password").size(14.0));
                    ui.add_space(58.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_password)
                            .password(true)
                            .desired_width(450.0),
                    );
                });

                ui.add_space(30.0);

                // Get Info button
                ui.vertical_centered(|ui| {
                    let can_get_info = !self.volume_container_path.is_empty()
                        && !self.volume_password.is_empty();

                    if ui.add_enabled(can_get_info, egui::Button::new(
                        egui::RichText::new("ℹ️ Get Volume Info").size(16.0).color(egui::Color32::WHITE))
                        .fill(egui::Color32::from_rgb(91, 206, 250))
                        .min_size(egui::vec2(250.0, 50.0))
                        .rounding(egui::Rounding::same(25.0))).clicked() {

                        match Container::open(
                            std::path::Path::new(&self.volume_container_path),
                            &self.volume_password,
                        ) {
                            Ok(container) => {
                                self.volume_info = Some(format!(
                                    "Container: {}\n\nData Size: {} bytes ({} MB)\nTotal Size: {} bytes ({} MB)\nSector Size: {} bytes\nActive Key Slots: {}\nUnlocked: {}",
                                    self.volume_container_path,
                                    container.data_size(),
                                    container.data_size() / 1024 / 1024,
                                    container.total_size(),
                                    container.total_size() / 1024 / 1024,
                                    container.sector_size(),
                                    container.key_slots().active_count(),
                                    if container.is_unlocked() { "Yes" } else { "No" }
                                ));
                                self.volume_status = "✓ Volume information retrieved".to_string();
                                self.volume_password.clear();
                            }
                            Err(e) => {
                                self.volume_info = None;
                                self.volume_status = format!("✗ Error: {}", e);
                            }
                        }
                    }
                });

                // Display info
                if let Some(ref info) = self.volume_info {
                    ui.add_space(20.0);
                    ui.separator();
                    ui.add_space(15.0);

                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(info)
                                    .size(12.0)
                                    .family(egui::FontFamily::Monospace),
                            );
                        });
                }

                // Status message
                if !self.volume_status.is_empty() {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new(&self.volume_status).size(13.0));
                    });
                }
            }

            VolumeTab::Password => {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("Password Management").size(18.0));
                });
                ui.add_space(20.0);

                // Container path
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Container Path").size(14.0));
                    ui.add_space(10.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_container_path)
                            .desired_width(450.0),
                    );
                    ui.add_space(10.0);
                    if ui.button("Browse...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.volume_container_path = path.display().to_string();
                        }
                    }
                });

                ui.add_space(15.0);

                // Current password
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Current Password").size(14.0));
                    ui.add_space(10.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_password)
                            .password(true)
                            .desired_width(450.0),
                    );
                });

                ui.add_space(15.0);

                // New password
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("New Password").size(14.0));
                    ui.add_space(34.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_password_confirm)
                            .password(true)
                            .desired_width(450.0),
                    );
                });

                ui.add_space(30.0);

                // Change password button
                ui.vertical_centered(|ui| {
                    let can_change = !self.volume_container_path.is_empty()
                        && !self.volume_password.is_empty()
                        && !self.volume_password_confirm.is_empty();

                    if ui
                        .add_enabled(
                            can_change,
                            egui::Button::new(
                                egui::RichText::new("🔐 Change Password")
                                    .size(16.0)
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(egui::Color32::from_rgb(91, 206, 250))
                            .min_size(egui::vec2(250.0, 50.0))
                            .rounding(egui::Rounding::same(25.0)),
                        )
                        .clicked()
                    {
                        match Container::open(
                            std::path::Path::new(&self.volume_container_path),
                            &self.volume_password,
                        ) {
                            Ok(mut container) => {
                                match container.change_password(&self.volume_password_confirm) {
                                    Ok(()) => {
                                        self.volume_status =
                                            "✓ Password changed successfully".to_string();
                                        self.volume_password.clear();
                                        self.volume_password_confirm.clear();
                                    }
                                    Err(e) => {
                                        self.volume_status = format!("✗ Error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                self.volume_status = format!("✗ Error opening container: {}", e);
                            }
                        }
                    }
                });

                // Status message
                if !self.volume_status.is_empty() {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new(&self.volume_status).size(13.0));
                    });
                }
            }
            VolumeTab::Security => {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("Security Settings").size(18.0));
                });
                ui.add_space(20.0);

                // Warning box
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(80, 30, 30))
                    .rounding(egui::Rounding::same(10.0))
                    .inner_margin(egui::Margin::same(15.0))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("⚠️ DURESS PASSWORD WARNING").size(16.0).color(egui::Color32::from_rgb(255, 200, 200)));
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new(
                            "A duress password is a self-destruct mechanism. When entered during unlock:\n\
                            • ALL key slots will be permanently destroyed\n\
                            • The volume will become PERMANENTLY inaccessible\n\
                            • Data recovery will be IMPOSSIBLE\n\
                            • The error will appear identical to a wrong password"
                        ).size(12.0).color(egui::Color32::from_rgb(255, 200, 200)));
                    });

                ui.add_space(20.0);

                // Container path
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Container Path").size(14.0));
                    ui.add_space(10.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_container_path)
                            .desired_width(450.0),
                    );
                    ui.add_space(10.0);
                    if ui.button("Browse...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.volume_container_path = path.display().to_string();
                            // Check if volume has duress password
                            self.has_duress_password = false;
                            self.duress_status.clear();
                        }
                    }
                });

                ui.add_space(15.0);

                // Container password to unlock
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Container Password").size(14.0));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.volume_password)
                            .password(true)
                            .desired_width(450.0),
                    );
                });

                ui.add_space(15.0);

                // Duress password
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Duress Password").size(14.0));
                    ui.add_space(18.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.duress_password)
                            .password(true)
                            .desired_width(450.0),
                    );
                });

                ui.add_space(15.0);

                // Confirm duress password
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Confirm Duress").size(14.0));
                    ui.add_space(27.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.duress_password_confirm)
                            .password(true)
                            .desired_width(450.0),
                    );
                });

                ui.add_space(30.0);

                // Buttons
                ui.horizontal(|ui| {
                    ui.add_space(100.0);

                    // Set duress password button
                    let can_set = !self.volume_container_path.is_empty()
                        && !self.volume_password.is_empty()
                        && !self.duress_password.is_empty()
                        && self.duress_password == self.duress_password_confirm
                        && self.duress_password != self.volume_password;

                    if ui
                        .add_enabled(
                            can_set,
                            egui::Button::new(
                                egui::RichText::new("🛡️ Set Duress Password")
                                    .size(14.0)
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(egui::Color32::from_rgb(180, 50, 50))
                            .min_size(egui::vec2(200.0, 45.0))
                            .rounding(egui::Rounding::same(20.0)),
                        )
                        .clicked()
                    {
                        match Container::open(
                            std::path::Path::new(&self.volume_container_path),
                            &self.volume_password,
                        ) {
                            Ok(mut container) => {
                                match container.set_duress_password(&self.duress_password) {
                                    Ok(()) => {
                                        self.duress_status =
                                            "✓ Duress password set successfully".to_string();
                                        self.has_duress_password = true;
                                        self.duress_password.clear();
                                        self.duress_password_confirm.clear();
                                    }
                                    Err(e) => {
                                        self.duress_status = format!("✗ Error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                self.duress_status = format!("✗ Error opening container: {}", e);
                            }
                        }
                    }

                    ui.add_space(20.0);

                    // Remove duress password button
                    let can_remove =
                        !self.volume_container_path.is_empty() && !self.volume_password.is_empty();

                    if ui
                        .add_enabled(
                            can_remove,
                            egui::Button::new(
                                egui::RichText::new("🗑️ Remove Duress Password")
                                    .size(14.0)
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(egui::Color32::from_rgb(100, 100, 100))
                            .min_size(egui::vec2(220.0, 45.0))
                            .rounding(egui::Rounding::same(20.0)),
                        )
                        .clicked()
                    {
                        match Container::open(
                            std::path::Path::new(&self.volume_container_path),
                            &self.volume_password,
                        ) {
                            Ok(mut container) => {
                                if !container.has_duress_password() {
                                    self.duress_status =
                                        "Note: No duress password is currently set".to_string();
                                } else {
                                    match container.remove_duress_password() {
                                        Ok(()) => {
                                            self.duress_status =
                                                "✓ Duress password removed".to_string();
                                            self.has_duress_password = false;
                                        }
                                        Err(e) => {
                                            self.duress_status = format!("✗ Error: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                self.duress_status = format!("✗ Error opening container: {}", e);
                            }
                        }
                    }
                });

                // Validation messages
                ui.add_space(15.0);
                if !self.duress_password.is_empty()
                    && !self.duress_password_confirm.is_empty()
                    && self.duress_password != self.duress_password_confirm
                {
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("⚠️ Duress passwords do not match")
                                .size(12.0)
                                .color(egui::Color32::from_rgb(255, 150, 150)),
                        );
                    });
                }

                if !self.duress_password.is_empty()
                    && !self.volume_password.is_empty()
                    && self.duress_password == self.volume_password
                {
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new(
                                "⚠️ Duress password must be different from container password",
                            )
                            .size(12.0)
                            .color(egui::Color32::from_rgb(255, 150, 150)),
                        );
                    });
                }

                // Status message
                if !self.duress_status.is_empty() {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new(&self.duress_status).size(13.0));
                    });
                }
            }
            VolumeTab::RemoteWipe => {
                self.render_remote_wipe_tab(ui);
            }
        }
    }

    /// Generates a QR code texture from a string
    #[cfg(feature = "gui")]
    fn generate_qr_texture(ctx: &egui::Context, data: &str) -> Option<egui::TextureHandle> {
        use qrcode::QrCode;

        // Generate QR code
        let code = match QrCode::new(data.as_bytes()) {
            Ok(c) => c,
            Err(_) => return None,
        };

        // Get the QR code as a pixel matrix
        let colors = code.to_colors();
        let width = code.width();

        // Scale factor for better visibility
        let scale = 4;
        let img_size = width * scale;

        // Create RGBA pixel data
        let mut pixels = vec![255u8; img_size * img_size * 4];

        for y in 0..width {
            for x in 0..width {
                let is_dark = colors[y * width + x] == qrcode::Color::Dark;
                let color = if is_dark { 0u8 } else { 255u8 };

                // Fill scaled pixels
                for sy in 0..scale {
                    for sx in 0..scale {
                        let px = x * scale + sx;
                        let py = y * scale + sy;
                        let idx = (py * img_size + px) * 4;
                        pixels[idx] = color; // R
                        pixels[idx + 1] = color; // G
                        pixels[idx + 2] = color; // B
                        pixels[idx + 3] = 255; // A
                    }
                }
            }
        }

        // Create egui texture
        let color_image = egui::ColorImage::from_rgba_unmultiplied([img_size, img_size], &pixels);

        Some(ctx.load_texture("qr_code", color_image, egui::TextureOptions::NEAREST))
    }

    #[cfg(feature = "encrypted-volumes")]
    fn render_remote_wipe_tab(&mut self, ui: &mut egui::Ui) {
        use tesseract_lib::volume::remote_wipe::WipeToken;

        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new("Remote Wipe Configuration").size(18.0));
        });
        ui.add_space(20.0);

        // Info box
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(40, 60, 80))
            .rounding(egui::Rounding::same(10.0))
            .inner_margin(egui::Margin::same(15.0))
            .show(ui, |ui| {
                ui.label(egui::RichText::new("📡 Remote Wipe").size(16.0).color(egui::Color32::from_rgb(91, 206, 250)));
                ui.add_space(10.0);
                ui.label(egui::RichText::new(
                    "Remote wipe allows you to destroy encryption keys across all devices via a cloud command.\n\
                    • Generate a wipe token and store it securely (e.g., password manager, safe)\n\
                    • Register keyfile paths that should be destroyed on wipe\n\
                    • Use the web dashboard to trigger wipe from any device"
                ).size(12.0).color(egui::Color32::from_rgb(200, 220, 240)));
            });

        ui.add_space(20.0);

        // Token generation section
        ui.label(egui::RichText::new("Wipe Token").size(16.0));
        ui.add_space(10.0);

        // Track if we need to generate a new QR code
        let mut generate_qr = false;
        let mut qr_token = String::new();

        if self.remote_wipe_token_display.is_empty() {
            // Generate new token button
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("🔑 Generate Wipe Token")
                            .size(14.0)
                            .color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(91, 206, 250))
                    .min_size(egui::vec2(200.0, 40.0))
                    .rounding(egui::Rounding::same(20.0)),
                )
                .clicked()
            {
                let token = WipeToken::generate();
                self.remote_wipe_token = token.to_hex().to_string();
                self.remote_wipe_token_display = self.remote_wipe_token.clone();
                self.remote_wipe_status =
                    "✓ Token generated - SAVE THIS TOKEN SECURELY!".to_string();
                generate_qr = true;
                qr_token = self.remote_wipe_token.clone();
            }
        } else {
            // Display existing token
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(30, 30, 30))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::same(12.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("Token:")
                                .size(12.0)
                                .color(egui::Color32::GRAY),
                        );
                        ui.add_space(10.0);
                        // Show truncated token with copy button
                        let display_token = if self.remote_wipe_token_display.len() > 32 {
                            format!("{}...", &self.remote_wipe_token_display[..32])
                        } else {
                            self.remote_wipe_token_display.clone()
                        };
                        ui.label(
                            egui::RichText::new(&display_token)
                                .size(11.0)
                                .color(egui::Color32::from_rgb(150, 255, 150))
                                .monospace(),
                        );
                    });
                });

            ui.add_space(10.0);

            ui.horizontal(|ui| {
                // Copy to clipboard button
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("📋 Copy Token")
                                .size(12.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(100, 100, 100))
                        .min_size(egui::vec2(120.0, 30.0))
                        .rounding(egui::Rounding::same(15.0)),
                    )
                    .clicked()
                {
                    ui.output_mut(|o| o.copied_text = self.remote_wipe_token_display.clone());
                    self.remote_wipe_status = "✓ Token copied to clipboard".to_string();
                }

                ui.add_space(10.0);

                // Regenerate token button
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("🔄 Regenerate")
                                .size(12.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(180, 100, 50))
                        .min_size(egui::vec2(120.0, 30.0))
                        .rounding(egui::Rounding::same(15.0)),
                    )
                    .clicked()
                {
                    let token = WipeToken::generate();
                    self.remote_wipe_token = token.to_hex().to_string();
                    self.remote_wipe_token_display = self.remote_wipe_token.clone();
                    self.remote_wipe_status =
                        "✓ New token generated - old token is now INVALID!".to_string();
                    generate_qr = true;
                    qr_token = self.remote_wipe_token.clone();
                }

                ui.add_space(10.0);

                // Clear token button
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("🗑️ Clear")
                                .size(12.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(180, 50, 50))
                        .min_size(egui::vec2(80.0, 30.0))
                        .rounding(egui::Rounding::same(15.0)),
                    )
                    .clicked()
                {
                    self.remote_wipe_token.clear();
                    self.remote_wipe_token_display.clear();
                    self.remote_wipe_qr_texture = None;
                    self.remote_wipe_status = "Token cleared".to_string();
                }

                ui.add_space(10.0);

                // Toggle QR code button
                if self.remote_wipe_qr_texture.is_some() {
                    let qr_btn_text = if self.remote_wipe_show_qr {
                        "Hide QR"
                    } else {
                        "Show QR"
                    };
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new(qr_btn_text)
                                    .size(12.0)
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(egui::Color32::from_rgb(70, 70, 120))
                            .min_size(egui::vec2(80.0, 30.0))
                            .rounding(egui::Rounding::same(15.0)),
                        )
                        .clicked()
                    {
                        self.remote_wipe_show_qr = !self.remote_wipe_show_qr;
                    }
                }
            });

            // Display QR code if available and visible
            if self.remote_wipe_show_qr {
                if let Some(ref texture) = self.remote_wipe_qr_texture {
                    ui.add_space(15.0);
                    ui.vertical_centered(|ui| {
                        egui::Frame::none()
                            .fill(egui::Color32::WHITE)
                            .rounding(egui::Rounding::same(8.0))
                            .inner_margin(egui::Margin::same(10.0))
                            .show(ui, |ui| {
                                ui.image(egui::load::SizedTexture::new(
                                    texture.id(),
                                    egui::vec2(200.0, 200.0),
                                ));
                            });
                        ui.add_space(5.0);
                        ui.label(
                            egui::RichText::new("Scan to copy token to password manager")
                                .size(11.0)
                                .color(egui::Color32::GRAY),
                        );
                    });
                } else if !self.remote_wipe_token_display.is_empty() {
                    // Generate QR code if token exists but no texture
                    generate_qr = true;
                    qr_token = self.remote_wipe_token_display.clone();
                }
            }
        }

        // Generate QR code texture if needed (done outside the UI code to avoid borrow issues)
        if generate_qr && !qr_token.is_empty() {
            if let Some(texture) = Self::generate_qr_texture(ui.ctx(), &qr_token) {
                self.remote_wipe_qr_texture = Some(texture);
            }
        }

        ui.add_space(25.0);
        ui.separator();
        ui.add_space(15.0);

        // Keyfile paths section
        ui.label(egui::RichText::new("Protected Keyfile Paths").size(16.0));
        ui.add_space(5.0);
        ui.label(
            egui::RichText::new(
                "Files at these paths will be securely destroyed when a wipe command is received.",
            )
            .size(11.0)
            .color(egui::Color32::GRAY),
        );
        ui.add_space(10.0);

        // List existing paths
        if !self.remote_wipe_keyfile_paths.is_empty() {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(40, 40, 40))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::same(10.0))
                .show(ui, |ui| {
                    let mut path_to_remove: Option<usize> = None;
                    for (idx, path) in self.remote_wipe_keyfile_paths.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("📄").size(12.0));
                            ui.label(egui::RichText::new(path).size(11.0).monospace());
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.small_button("✗").clicked() {
                                        path_to_remove = Some(idx);
                                    }
                                },
                            );
                        });
                    }
                    if let Some(idx) = path_to_remove {
                        self.remote_wipe_keyfile_paths.remove(idx);
                    }
                });
            ui.add_space(10.0);
        }

        // Add new path
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.remote_wipe_new_path)
                    .hint_text("Enter keyfile path...")
                    .desired_width(400.0),
            );
            ui.add_space(10.0);
            if ui.button("Browse...").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.remote_wipe_new_path = path.display().to_string();
                }
            }
            ui.add_space(10.0);
            if ui
                .add_enabled(
                    !self.remote_wipe_new_path.is_empty(),
                    egui::Button::new("+ Add"),
                )
                .clicked()
            {
                if !self
                    .remote_wipe_keyfile_paths
                    .contains(&self.remote_wipe_new_path)
                {
                    self.remote_wipe_keyfile_paths
                        .push(self.remote_wipe_new_path.clone());
                }
                self.remote_wipe_new_path.clear();
            }
        });

        ui.add_space(25.0);
        ui.separator();
        ui.add_space(15.0);

        // Settings
        ui.label(egui::RichText::new("Settings").size(16.0));
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.checkbox(&mut self.remote_wipe_enabled, "");
            ui.label("Enable remote wipe capability");
        });

        ui.add_space(5.0);

        ui.horizontal(|ui| {
            ui.checkbox(&mut self.remote_wipe_require_confirmation, "");
            ui.label("Require confirmation before destroying keys");
        });

        ui.add_space(5.0);
        ui.label(egui::RichText::new("When enabled, wipe commands require a second confirmation command within 5 minutes.")
            .size(11.0).color(egui::Color32::GRAY));

        // Status message
        if !self.remote_wipe_status.is_empty() {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                let color = if self.remote_wipe_status.starts_with("✓") {
                    egui::Color32::from_rgb(100, 255, 100)
                } else if self.remote_wipe_status.starts_with("✗") {
                    egui::Color32::from_rgb(255, 100, 100)
                } else {
                    egui::Color32::from_rgb(200, 200, 200)
                };
                ui.label(
                    egui::RichText::new(&self.remote_wipe_status)
                        .size(13.0)
                        .color(color),
                );
            });
        }

        ui.add_space(20.0);

        // Web dashboard link
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(50, 50, 70))
            .rounding(egui::Rounding::same(10.0))
            .inner_margin(egui::Margin::same(15.0))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new("🌐 Web Dashboard")
                        .size(14.0)
                        .color(egui::Color32::from_rgb(91, 206, 250)),
                );
                ui.add_space(5.0);
                ui.label(
                    egui::RichText::new(
                        "To trigger a remote wipe, use the web dashboard from any device.\n\
                    You'll need your wipe token and volume ID.",
                    )
                    .size(11.0)
                    .color(egui::Color32::from_rgb(180, 180, 200)),
                );
            });
    }
}

impl eframe::App for CryptorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process system tray events
        if let Some(ref tray) = self.tray_manager {
            if let Some(event) = tray.process_events() {
                match event {
                    tray::TrayEvent::ToggleWindow => {
                        self.window_visible = !self.window_visible;
                        if self.window_visible {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        } else {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                        }
                    }
                    tray::TrayEvent::QuickEncrypt => {
                        self.window_visible = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        self.mode = Some(Mode::Encrypt);
                        self.select_input_file();
                    }
                    tray::TrayEvent::QuickDecrypt => {
                        self.window_visible = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        self.mode = Some(Mode::Decrypt);
                        self.select_input_file();
                    }
                    tray::TrayEvent::ShowSettings => {
                        self.window_visible = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        self.show_settings = true;
                    }
                    tray::TrayEvent::Quit => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
        }

        // Update tray status
        if let Some(ref mut tray) = self.tray_manager {
            if self.is_processing {
                tray.set_status("Processing...");
            } else if self.is_processing_queue {
                tray.set_status(&format!("Processing queue ({} items)", self.queue.len()));
            } else {
                tray.set_status("Ready");
            }
        }

        // Request repaint to keep checking for tray events
        ctx.request_repaint();

        // Draw gradient background
        let painter = ctx.layer_painter(egui::LayerId::background());
        let rect = ctx.screen_rect();

        // Trans pride gradient: blue -> pink
        let trans_blue = egui::Color32::from_rgb(135, 206, 250);
        let trans_pink = egui::Color32::from_rgb(245, 169, 200);

        // Create gradient mesh
        let mesh = {
            let mut mesh = egui::Mesh::default();
            mesh.colored_vertex(rect.left_top(), trans_blue);
            mesh.colored_vertex(rect.right_top(), trans_pink.gamma_multiply(0.6));
            mesh.colored_vertex(rect.left_bottom(), trans_blue.gamma_multiply(0.8));
            mesh.colored_vertex(rect.right_bottom(), trans_pink);
            mesh.add_triangle(0, 1, 2);
            mesh.add_triangle(1, 2, 3);
            mesh
        };
        painter.add(egui::Shape::mesh(mesh));

        // Menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if self.tray_manager.is_some() && ui.button("Minimize to Tray").clicked() {
                        self.window_visible = false;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                        ui.close_menu();
                    }
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Queue", |ui| {
                    if ui
                        .button(format!("📋 View Queue ({})", self.queue.len()))
                        .clicked()
                    {
                        self.show_queue_panel = true;
                        ui.close_menu();
                    }
                });

                #[cfg(feature = "encrypted-volumes")]
                ui.menu_button("Volumes", |ui| {
                    if ui.button("📦 Manage Volumes").clicked() {
                        self.mode = Some(Mode::Volume);
                        ui.close_menu();
                    }
                });

                ui.menu_button("Settings", |ui| {
                    if ui.button("⚙ Open Settings").clicked() {
                        self.show_settings = true;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        ui.close_menu();
                    }
                });
            });
        });

        // Queue panel window
        if self.show_queue_panel {
            self.render_queue_panel(ctx);
        }

        // Settings panel window
        if self.show_settings {
            self.render_settings_panel(ctx);
        }

        // Keyfile generator window
        #[cfg(feature = "post-quantum")]
        if self.show_keyfile_generator {
            self.render_keyfile_generator(ctx);
        }

        // Main content panel
        egui::CentralPanel::default()
            .frame(egui::Frame::none())
            .show(ctx, |ui| {
                ui.add_space(60.0);

                // Center the main panel
                ui.vertical_centered(|ui| {
                    let panel_frame = egui::Frame::default()
                        .fill(egui::Color32::from_rgba_unmultiplied(
                            255,
                            255,
                            255,
                            self.settings.panel_transparency,
                        ))
                        .rounding(egui::Rounding::same(20.0))
                        .inner_margin(egui::Margin::same(50.0))
                        .shadow(egui::epaint::Shadow {
                            offset: egui::Vec2::new(0.0, 8.0),
                            blur: 30.0,
                            spread: 0.0,
                            color: egui::Color32::from_black_alpha(60),
                        });

                    panel_frame.show(ui, |ui| {
                        ui.set_width(850.0);

                        // Title
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("Tesseract")
                                    .size(42.0)
                                    .color(egui::Color32::from_rgb(50, 50, 50)),
                            );
                        });

                        ui.add_space(30.0);

                        // Mode label
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("Mode").size(16.0));
                            ui.add_space(10.0);

                            // Mode buttons
                            ui.horizontal(|ui| {
                                ui.allocate_space(egui::vec2(250.0, 0.0));

                                let encrypt_color = if self.mode == Some(Mode::Encrypt) {
                                    egui::Color32::from_rgb(91, 206, 250)
                                } else {
                                    egui::Color32::from_rgb(200, 200, 200)
                                };

                                let decrypt_color = if self.mode == Some(Mode::Decrypt) {
                                    egui::Color32::from_rgb(245, 169, 184)
                                } else {
                                    egui::Color32::from_rgb(200, 200, 200)
                                };

                                // Encrypt button
                                let encrypt_btn = egui::Button::new(
                                    egui::RichText::new("🔐 Encrypt")
                                        .size(16.0)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(encrypt_color)
                                .min_size(egui::vec2(140.0, 45.0))
                                .rounding(egui::Rounding::same(25.0));

                                if ui.add_enabled(!self.is_processing, encrypt_btn).clicked() {
                                    self.mode = Some(Mode::Encrypt);
                                    if !self.input_path.is_empty() {
                                        self.output_path = format!("{}.enc", self.input_path);
                                    }
                                }

                                ui.add_space(10.0);

                                // Decrypt button
                                let decrypt_btn = egui::Button::new(
                                    egui::RichText::new("🔓 Decrypt")
                                        .size(16.0)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(decrypt_color)
                                .min_size(egui::vec2(140.0, 45.0))
                                .rounding(egui::Rounding::same(25.0));

                                if ui.add_enabled(!self.is_processing, decrypt_btn).clicked() {
                                    self.mode = Some(Mode::Decrypt);
                                    if !self.input_path.is_empty() {
                                        self.output_path = if self.input_path.ends_with(".enc") {
                                            self.input_path.trim_end_matches(".enc").to_string()
                                        } else {
                                            format!("{}.dec", self.input_path)
                                        };
                                    }
                                }

                                ui.add_space(10.0);

                                // Volume button
                                #[cfg(feature = "encrypted-volumes")]
                                {
                                    let volume_color = if self.mode == Some(Mode::Volume) {
                                        egui::Color32::from_rgb(245, 169, 184)
                                    } else {
                                        egui::Color32::from_rgb(200, 200, 200)
                                    };

                                    let volume_btn = egui::Button::new(
                                        egui::RichText::new("💾 Volume")
                                            .size(16.0)
                                            .color(egui::Color32::WHITE),
                                    )
                                    .fill(volume_color)
                                    .min_size(egui::vec2(140.0, 45.0))
                                    .rounding(egui::Rounding::same(25.0));

                                    if ui.add_enabled(!self.is_processing, volume_btn).clicked() {
                                        self.mode = Some(Mode::Volume);
                                    }
                                }
                            });
                        });

                        ui.add_space(30.0);

                        // Mode-specific UI content
                        match &self.mode {
                            Some(Mode::Encrypt) | Some(Mode::Decrypt) | None => {
                                // File encryption/decryption UI

                                // Input file row
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Input File").size(14.0));
                                    ui.add_space(20.0);
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.input_path)
                                            .desired_width(500.0)
                                            .interactive(false),
                                    );
                                    ui.add_space(10.0);
                                    let browse_btn = egui::Button::new("Browse...")
                                        .fill(egui::Color32::from_rgb(200, 230, 255))
                                        .min_size(egui::vec2(100.0, 30.0));
                                    if ui.add_enabled(!self.is_processing, browse_btn).clicked() {
                                        self.select_input_file();
                                    }
                                });

                                ui.add_space(15.0);

                                // Output file row
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Output File").size(14.0));
                                    ui.add_space(10.0);
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.output_path)
                                            .desired_width(500.0),
                                    );
                                    ui.add_space(10.0);
                                    let browse_btn = egui::Button::new("Browse...")
                                        .fill(egui::Color32::from_rgb(200, 230, 255))
                                        .min_size(egui::vec2(100.0, 30.0));
                                    if ui.add_enabled(!self.is_processing, browse_btn).clicked() {
                                        self.select_output_file();
                                    }
                                });

                                ui.add_space(15.0);

                                // Password row
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Password").size(14.0));
                                    ui.add_space(22.0);
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.password)
                                            .password(true)
                                            .desired_width(500.0),
                                    );
                                    // Spacer to match Browse button width in file rows
                                    ui.add_space(120.0);
                                });

                                // Confirm password row (only for encryption)
                                if self.mode == Some(Mode::Encrypt) {
                                    ui.add_space(15.0);
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("Confirm").size(14.0));
                                        ui.add_space(30.0);
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.confirm_password)
                                                .password(true)
                                                .desired_width(500.0),
                                        );
                                        // Spacer to match Browse button width in file rows
                                        ui.add_space(120.0);
                                    });
                                }

                                ui.add_space(20.0);

                                // PQC Keyfile section (required for encryption)
                                #[cfg(feature = "post-quantum")]
                                {
                                    ui.separator();
                                    ui.add_space(10.0);

                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("🔑 Quantum-Resistant Keyfile (Required)").size(14.0).color(egui::Color32::from_rgb(91, 140, 200)));
                                    });

                                    ui.add_space(10.0);

                                    // Keyfile path row
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("Keyfile").size(14.0));
                                        ui.add_space(30.0);
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.keyfile_path)
                                                .desired_width(500.0)
                                                .interactive(false),
                                        );
                                        ui.add_space(10.0);
                                        let browse_btn = egui::Button::new("Browse...")
                                            .fill(egui::Color32::from_rgb(200, 230, 255))
                                            .min_size(egui::vec2(100.0, 30.0));
                                        if ui.add_enabled(!self.is_processing, browse_btn).clicked() {
                                            if let Some(path) = rfd::FileDialog::new()
                                                .add_filter("Tesseract Keyfile", &["tkf"])
                                                .pick_file()
                                            {
                                                self.keyfile_path = path.display().to_string();
                                            }
                                        }
                                    });

                                    // Keyfile password (if keyfile is protected)
                                    if !self.keyfile_path.is_empty() {
                                        ui.add_space(10.0);
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new("Keyfile Pass").size(14.0));
                                            ui.add_space(5.0);
                                            ui.add(
                                                egui::TextEdit::singleline(&mut self.keyfile_password)
                                                    .password(true)
                                                    .desired_width(500.0)
                                                    .hint_text("Leave empty if keyfile is unprotected"),
                                            );
                                            ui.add_space(120.0);
                                        });
                                    }

                                    ui.add_space(10.0);

                                    // Generate keyfile button
                                    ui.horizontal(|ui| {
                                        ui.add_space(85.0);
                                        let gen_btn = egui::Button::new(
                                            egui::RichText::new("🔧 Generate New Keyfile")
                                                .size(13.0)
                                                .color(egui::Color32::WHITE),
                                        )
                                        .fill(egui::Color32::from_rgb(100, 180, 100))
                                        .min_size(egui::vec2(180.0, 32.0))
                                        .rounding(egui::Rounding::same(16.0));

                                        if ui.add_enabled(!self.is_processing, gen_btn).clicked() {
                                            self.show_keyfile_generator = true;
                                            // Default output path
                                            if self.keyfile_output_path.is_empty() {
                                                self.keyfile_output_path = dirs::document_dir()
                                                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                                                    .join("my-keyfile.tkf")
                                                    .display()
                                                    .to_string();
                                            }
                                        }

                                        ui.add_space(10.0);
                                        ui.label(
                                            egui::RichText::new("A keyfile is required for quantum-resistant encryption")
                                                .size(11.0)
                                                .color(egui::Color32::from_rgb(120, 120, 120)),
                                        );
                                    });
                                }

                                ui.add_space(30.0);

                                // Action buttons
                                ui.vertical_centered(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.add_space(80.0);

                                        let button_text = if self.is_processing {
                                            "⏳ Processing..."
                                        } else {
                                            match &self.mode {
                                                Some(Mode::Encrypt) => "🔐 Encrypt File",
                                                Some(Mode::Decrypt) => "🔓 Decrypt File",
                                                Some(Mode::Volume) => "📦 Manage Volumes",
                                                None => "Select Mode First",
                                            }
                                        };

                                        // Keyfile is required for encryption
                                        #[cfg(feature = "post-quantum")]
                                        let keyfile_valid = !self.keyfile_path.is_empty();
                                        #[cfg(not(feature = "post-quantum"))]
                                        let keyfile_valid = true;

                                        let button_enabled = !self.is_processing
                                            && !self.is_processing_queue
                                            && self.mode.is_some()
                                            && !self.input_path.is_empty()
                                            && !self.output_path.is_empty()
                                            && !self.password.is_empty()
                                            && keyfile_valid;

                                        let button_color = egui::Color32::from_rgb(91, 206, 250);

                                        let action_btn = egui::Button::new(
                                            egui::RichText::new(button_text)
                                                .size(18.0)
                                                .color(egui::Color32::WHITE),
                                        )
                                        .fill(button_color)
                                        .min_size(egui::vec2(280.0, 50.0))
                                        .rounding(egui::Rounding::same(25.0));

                                        if ui.add_enabled(button_enabled, action_btn).clicked() {
                                            self.process_file();
                                        }

                                        ui.add_space(15.0);

                                        // Add to Queue button
                                        let queue_btn = egui::Button::new(
                                            egui::RichText::new("➕ Add to Queue")
                                                .size(18.0)
                                                .color(egui::Color32::WHITE),
                                        )
                                        .fill(egui::Color32::from_rgb(245, 169, 184))
                                        .min_size(egui::vec2(200.0, 50.0))
                                        .rounding(egui::Rounding::same(25.0));

                                        if ui.add_enabled(button_enabled, queue_btn).clicked() {
                                            self.add_to_queue();
                                        }
                                    });
                                });

                                ui.add_space(20.0);

                                // Progress bar
                                if self.is_processing || self.progress > 0.0 {
                                    ui.vertical_centered(|ui| {
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}%",
                                                (self.progress * 100.0) as i32
                                            ))
                                            .size(14.0),
                                        );
                                        ui.add_space(5.0);

                                        // Custom striped progress bar
                                        let progress_bar_height = 30.0;
                                        let progress_bar_width = 650.0;
                                        let (rect, _response) = ui.allocate_exact_size(
                                            egui::vec2(progress_bar_width, progress_bar_height),
                                            egui::Sense::hover(),
                                        );

                                        // Background
                                        ui.painter().rect_filled(
                                            rect,
                                            egui::Rounding::same(15.0),
                                            egui::Color32::from_rgb(220, 220, 220),
                                        );

                                        // Progress fill with pink/white stripes
                                        let fill_width = rect.width() * self.progress;
                                        let fill_rect = egui::Rect::from_min_size(
                                            rect.min,
                                            egui::vec2(fill_width, rect.height()),
                                        );

                                        if fill_width > 0.0 {
                                            ui.painter().rect_filled(
                                                fill_rect,
                                                egui::Rounding::same(15.0),
                                                egui::Color32::from_rgb(245, 169, 184),
                                            );
                                        }

                                        // Border
                                        ui.painter().rect_stroke(
                                            rect,
                                            egui::Rounding::same(15.0),
                                            egui::Stroke::new(
                                                2.0,
                                                egui::Color32::from_rgb(91, 206, 250),
                                            ),
                                        );
                                    });

                                    ui.add_space(10.0);
                                }

                                // Status message
                                if !self.status_message.is_empty() {
                                    ui.vertical_centered(|ui| {
                                        ui.label(
                                            egui::RichText::new(&self.status_message)
                                                .size(13.0)
                                                .color(egui::Color32::from_rgb(80, 80, 80)),
                                        );
                                    });
                                }
                            }
                            #[cfg(feature = "encrypted-volumes")]
                            Some(Mode::Volume) => {
                                // Volume management UI
                                self.render_volume_ui(ui);
                            }
                            #[cfg(not(feature = "encrypted-volumes"))]
                            Some(Mode::Volume) => {
                                ui.vertical_centered(|ui| {
                                    ui.label(
                                        egui::RichText::new("Volume feature not enabled")
                                            .size(14.0)
                                            .color(egui::Color32::from_rgb(200, 100, 100)),
                                    );
                                });
                            }
                        }

                        ui.add_space(20.0);

                        // Footer badges
                        ui.vertical_centered(|ui| {
                            ui.horizontal(|ui| {
                                ui.allocate_space(egui::vec2(100.0, 0.0));

                                // AES badge
                                let aes_badge = egui::Button::new(
                                    egui::RichText::new("🔒 AES-256-GCM")
                                        .size(12.0)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(100, 180, 230))
                                .min_size(egui::vec2(140.0, 35.0))
                                .rounding(egui::Rounding::same(18.0));
                                ui.add_enabled(false, aes_badge);

                                ui.add_space(10.0);

                                // Argon2id badge
                                let argon_badge = egui::Button::new(
                                    egui::RichText::new("🌀 Argon2id")
                                        .size(12.0)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(235, 150, 170))
                                .min_size(egui::vec2(110.0, 35.0))
                                .rounding(egui::Rounding::same(18.0));
                                ui.add_enabled(false, argon_badge);

                                ui.add_space(10.0);

                                // Authenticated badge
                                let auth_badge = egui::Button::new(
                                    egui::RichText::new("✓ Authenticated")
                                        .size(12.0)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(100, 180, 230))
                                .min_size(egui::vec2(140.0, 35.0))
                                .rounding(egui::Rounding::same(18.0));
                                ui.add_enabled(false, auth_badge);

                                // YubiKey badge (only shown when enabled)
                                if self.settings.yubikey_enabled {
                                    ui.add_space(10.0);
                                    let yubikey_badge = egui::Button::new(
                                        egui::RichText::new("🔑 YubiKey 2FA")
                                            .size(12.0)
                                            .color(egui::Color32::WHITE),
                                    )
                                    .fill(egui::Color32::from_rgb(80, 180, 80))
                                    .min_size(egui::vec2(120.0, 35.0))
                                    .rounding(egui::Rounding::same(18.0));
                                    ui.add_enabled(false, yubikey_badge);
                                }
                            });
                        });

                        ui.add_space(10.0);
                    });
                });
            });
    }
}

fn encrypt_file(
    input_path: &str,
    output_path: &str,
    password: &str,
    use_compression: bool,
    yubikey_enabled: bool,
    yubikey_slot: u8,
) -> Result<String, Box<dyn std::error::Error>> {
    use rand::rngs::SysRng;
    use rand_core::TryRng;

    let input = PathBuf::from(input_path);
    let output = PathBuf::from(output_path);

    // If YubiKey is enabled, use the HSM-aware encryption
    #[cfg(feature = "yubikey")]
    if yubikey_enabled {
        use tesseract_lib::hsm::yubikey::{YubiKey, YubiKeyConfig, YubiKeySlot};
        use tesseract_lib::hsm::HardwareSecurityModule;

        let yk_slot = match yubikey_slot {
            1 => YubiKeySlot::Slot1,
            _ => YubiKeySlot::Slot2,
        };

        let config = YubiKeyConfig {
            slot: yk_slot,
            ..Default::default()
        };

        let yubikey = YubiKey::with_config(config)?;

        if !yubikey.is_available() {
            return Err("No YubiKey detected. Please insert your YubiKey and try again.".into());
        }

        tesseract_lib::encrypt_file_with_hsm(&input, &output, password, &yubikey)?;
        return Ok(format!(
            "File encrypted with YubiKey 2FA: {}",
            output.display()
        ));
    }

    #[cfg(not(feature = "yubikey"))]
    if yubikey_enabled {
        return Err("YubiKey support not compiled in. Rebuild with --features yubikey".into());
    }

    // Standard encryption without YubiKey
    let _ = yubikey_slot; // Suppress warning when yubikey feature is disabled

    let mut config = StreamConfig::default();
    if use_compression {
        config = config.with_compression(true);
    }

    let reader = ChunkedReader::open(&input, config)?;
    let kdf = Argon2Kdf::default();
    let salt = kdf.generate_salt();
    let key = kdf.derive_key(password.as_bytes(), &salt)?;

    let mut base_nonce = [0u8; 12];
    SysRng
        .try_fill_bytes(&mut base_nonce)
        .map_err(|e| format!("RNG error: {}", e))?;

    let encryptor = ChunkedEncryptor::new(
        reader,
        Box::new(AesGcmEncryptor::new()),
        key,
        base_nonce,
        String::from_utf8(salt).unwrap(),
    );

    let mut output_file = std::fs::File::create(&output)?;
    encryptor.encrypt_to(&mut output_file)?;

    Ok(format!("File encrypted successfully: {}", output.display()))
}

fn decrypt_file(
    input_path: &str,
    output_path: &str,
    password: &str,
    yubikey_enabled: bool,
    yubikey_slot: u8,
) -> Result<String, Box<dyn std::error::Error>> {
    let input = PathBuf::from(input_path);
    let output = PathBuf::from(output_path);

    // If YubiKey is enabled, use the HSM-aware decryption
    #[cfg(feature = "yubikey")]
    if yubikey_enabled {
        use tesseract_lib::hsm::yubikey::{YubiKey, YubiKeyConfig, YubiKeySlot};
        use tesseract_lib::hsm::HardwareSecurityModule;

        let yk_slot = match yubikey_slot {
            1 => YubiKeySlot::Slot1,
            _ => YubiKeySlot::Slot2,
        };

        let config = YubiKeyConfig {
            slot: yk_slot,
            ..Default::default()
        };

        let yubikey = YubiKey::with_config(config)?;

        if !yubikey.is_available() {
            return Err("No YubiKey detected. Please insert your YubiKey and try again.".into());
        }

        tesseract_lib::decrypt_file_with_hsm(&input, &output, password, &yubikey)?;
        return Ok(format!(
            "File decrypted with YubiKey 2FA: {}",
            output.display()
        ));
    }

    #[cfg(not(feature = "yubikey"))]
    if yubikey_enabled {
        return Err("YubiKey support not compiled in. Rebuild with --features yubikey".into());
    }

    // Standard decryption without YubiKey
    let _ = yubikey_slot; // Suppress warning when yubikey feature is disabled

    let input_file = std::fs::File::open(&input)?;
    let decryptor = ChunkedDecryptor::new(
        input_file,
        Box::new(AesGcmEncryptor::new()),
        Zeroizing::new([0u8; 32]),
    )?;

    let salt = decryptor.header().salt.as_bytes();
    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key(password.as_bytes(), salt)?;

    let input_file = std::fs::File::open(&input)?;
    let mut decryptor = ChunkedDecryptor::new(input_file, Box::new(AesGcmEncryptor::new()), key)?;

    let mut output_file = std::fs::File::create(&output)?;
    decryptor.decrypt_to(&mut output_file)?;

    Ok(format!("File decrypted successfully: {}", output.display()))
}

/// Encrypt a file using PQC keyfile for quantum-resistant encryption
#[cfg(feature = "post-quantum")]
fn encrypt_file_with_keyfile(
    input_path: &str,
    output_path: &str,
    password: &str,
    keyfile_path: &str,
    keyfile_password: Option<&str>,
    use_compression: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    use rand_core::TryRng;
    use std::io::Write;
    use tesseract_lib::crypto::aes_gcm::AesGcmEncryptor;
    use tesseract_lib::crypto::kdf::{generate_salt_string, Argon2Kdf};
    use tesseract_lib::crypto::keyfile::{combine_keys_hkdf, PqcKeyfile};
    use tesseract_lib::crypto::Encryptor;
    use tesseract_lib::crypto::KeyDerivation;

    let input = PathBuf::from(input_path);
    let output = PathBuf::from(output_path);
    let kf_path = PathBuf::from(keyfile_path);

    // Load keyfile
    let keyfile = PqcKeyfile::load(&kf_path, keyfile_password)?;

    // Generate salt for Argon2
    let salt = generate_salt_string();

    // Derive classical key from password
    let kdf = Argon2Kdf::default();
    let classical_key = kdf.derive_key(password.as_bytes(), salt.as_ref().as_bytes())?;

    // Encapsulate to get PQC shared secret and ciphertext
    let (pqc_ciphertext, pqc_shared_secret) = keyfile.encapsulate()?;

    // Combine classical and PQC keys using HKDF
    let hybrid_key = combine_keys_hkdf(&classical_key, &pqc_shared_secret)?;

    // Read input file (with optional decompression handled at read time)
    let plaintext = if use_compression {
        // For now, just read the file - compression can be added later
        std::fs::read(&input)?
    } else {
        std::fs::read(&input)?
    };

    // Encrypt using AES-256-GCM with the hybrid key
    let encryptor = AesGcmEncryptor::new();
    let mut nonce = [0u8; 12];
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| format!("RNG error: {}", e))?;

    let ciphertext = encryptor.encrypt(&hybrid_key, &nonce, &plaintext)?;

    // Write output file with PQC header
    // Format: TESS-PQE1 (8 bytes) + salt (32 bytes) + nonce (12) + ciphertext_len (4) + pqc_ciphertext + encrypted_data
    let mut output_file = std::fs::File::create(&output)?;

    // Magic bytes for PQC encrypted file (8 bytes)
    output_file.write_all(b"TESSPQE1")?;

    // Salt as base64 string (padded to 32 bytes)
    let salt_bytes = salt.as_ref().as_bytes();
    let mut salt_padded = [0u8; 32];
    let copy_len = salt_bytes.len().min(32);
    salt_padded[..copy_len].copy_from_slice(&salt_bytes[..copy_len]);
    output_file.write_all(&salt_padded)?;

    // Nonce
    output_file.write_all(&nonce)?;

    // Compression flag (1 byte)
    output_file.write_all(&[if use_compression { 1 } else { 0 }])?;

    // PQC ciphertext length and data
    let ct_len = pqc_ciphertext.len() as u32;
    output_file.write_all(&ct_len.to_le_bytes())?;
    output_file.write_all(&pqc_ciphertext)?;

    // Encrypted data
    output_file.write_all(&ciphertext)?;

    Ok(format!(
        "File encrypted with quantum resistance (NIST Level 5): {}",
        output.display()
    ))
}

/// Decrypt a file using PQC keyfile for quantum-resistant decryption
#[cfg(feature = "post-quantum")]
fn decrypt_file_with_keyfile(
    input_path: &str,
    output_path: &str,
    password: &str,
    keyfile_path: &str,
    keyfile_password: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Read;
    use tesseract_lib::crypto::aes_gcm::AesGcmEncryptor;
    use tesseract_lib::crypto::kdf::Argon2Kdf;
    use tesseract_lib::crypto::keyfile::{combine_keys_hkdf, PqcKeyfile};
    use tesseract_lib::crypto::Encryptor;
    use tesseract_lib::crypto::KeyDerivation;

    let input = PathBuf::from(input_path);
    let output = PathBuf::from(output_path);
    let kf_path = PathBuf::from(keyfile_path);

    // Load keyfile
    let keyfile = PqcKeyfile::load(&kf_path, keyfile_password)?;

    // Read and parse input file
    let mut input_file = std::fs::File::open(&input)?;

    // Read magic bytes (8 bytes: "TESSPQE1")
    let mut magic = [0u8; 8];
    input_file.read_exact(&mut magic)?;

    if &magic != b"TESSPQE1" {
        return Err("Not a PQC-encrypted file (missing TESSPQE1 header)".into());
    }

    // Read salt (32 bytes padded)
    let mut salt_padded = [0u8; 32];
    input_file.read_exact(&mut salt_padded)?;

    // Find null terminator or end of salt
    let salt_len = salt_padded
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(salt_padded.len());
    let salt_str = std::str::from_utf8(&salt_padded[..salt_len])?;

    // Read nonce (12 bytes)
    let mut nonce = [0u8; 12];
    input_file.read_exact(&mut nonce)?;

    // Read compression flag (1 byte)
    let mut compression_flag = [0u8; 1];
    input_file.read_exact(&mut compression_flag)?;
    let _use_compression = compression_flag[0] != 0;

    // Read PQC ciphertext length and data
    let mut ct_len_bytes = [0u8; 4];
    input_file.read_exact(&mut ct_len_bytes)?;
    let ct_len = u32::from_le_bytes(ct_len_bytes) as usize;

    let mut pqc_ciphertext = vec![0u8; ct_len];
    input_file.read_exact(&mut pqc_ciphertext)?;

    // Read encrypted data
    let mut encrypted_data = Vec::new();
    input_file.read_to_end(&mut encrypted_data)?;

    // Derive classical key from password
    let kdf = Argon2Kdf::default();
    let classical_key = kdf.derive_key(password.as_bytes(), salt_str.as_bytes())?;

    // Decapsulate to get PQC shared secret
    let pqc_shared_secret = keyfile.decapsulate(&pqc_ciphertext)?;

    // Combine classical and PQC keys using HKDF
    let hybrid_key = combine_keys_hkdf(&classical_key, &pqc_shared_secret)?;

    // Decrypt using AES-256-GCM with the hybrid key
    let encryptor = AesGcmEncryptor::new();
    let plaintext = encryptor.decrypt(&hybrid_key, &nonce, &encrypted_data)?;

    // Write output file
    std::fs::write(&output, plaintext.as_slice())?;

    Ok(format!(
        "File decrypted successfully (quantum-resistant): {}",
        output.display()
    ))
}

/// Parse size string (e.g., "100M", "1G") into bytes
#[cfg(feature = "encrypted-volumes")]
fn parse_size(size_str: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let size_str = size_str.trim().to_uppercase();

    if size_str.is_empty() {
        return Err("Size string is empty".into());
    }

    if size_str.ends_with('K') {
        let num = size_str[..size_str.len() - 1].parse::<u64>()?;
        Ok(num * 1024)
    } else if size_str.ends_with('M') {
        let num = size_str[..size_str.len() - 1].parse::<u64>()?;
        Ok(num * 1024 * 1024)
    } else if size_str.ends_with('G') {
        let num = size_str[..size_str.len() - 1].parse::<u64>()?;
        Ok(num * 1024 * 1024 * 1024)
    } else if size_str.ends_with('T') {
        let num = size_str[..size_str.len() - 1].parse::<u64>()?;
        Ok(num * 1024 * 1024 * 1024 * 1024)
    } else {
        // No suffix, parse as raw bytes
        Ok(size_str.parse::<u64>()?)
    }
}
