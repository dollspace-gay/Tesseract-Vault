@echo off
REM Build script for optimizing WASM bundle size
REM Tests different configurations and optimization levels

echo ========================================
echo WASM Bundle Size Optimization
echo ========================================
echo.

REM Create output directory
if not exist "pkg\benchmarks" mkdir pkg\benchmarks

REM Build 1: Full features (default)
echo [1/3] Building with all features (wasm-full)...
wasm-pack build --target web --out-dir pkg/benchmarks/full -- --features wasm-full 2>nul
if exist pkg\benchmarks\full\secure_cryptor_bg.wasm (
    for %%I in (pkg\benchmarks\full\secure_cryptor_bg.wasm) do (
        echo   Size: %%~zI bytes ^(%%~zI / 1024 KB^)
    )
) else (
    echo   Build failed
)
echo.

REM Build 2: No PQC
echo [2/3] Building without post-quantum crypto...
wasm-pack build --target web --out-dir pkg/benchmarks/no-pqc -- --no-default-features --features compression 2>nul
if exist pkg\benchmarks\no-pqc\secure_cryptor_bg.wasm (
    for %%I in (pkg\benchmarks\no-pqc\secure_cryptor_bg.wasm) do (
        echo   Size: %%~zI bytes ^(%%~zI / 1024 KB^)
    )
) else (
    echo   Build failed
)
echo.

REM Build 3: Minimal (no PQC, no compression)
echo [3/3] Building minimal ^(wasm-minimal^)...
wasm-pack build --target web --out-dir pkg/benchmarks/minimal -- --no-default-features --features wasm-minimal 2>nul
if exist pkg\benchmarks\minimal\secure_cryptor_bg.wasm (
    for %%I in (pkg\benchmarks\minimal\secure_cryptor_bg.wasm) do (
        echo   Size: %%~zI bytes ^(%%~zI / 1024 KB^)
    )
) else (
    echo   Build failed
)
echo.

echo ========================================
echo Size Comparison:
echo ========================================
echo Full features:
if exist pkg\benchmarks\full\secure_cryptor_bg.wasm (
    for %%I in (pkg\benchmarks\full\secure_cryptor_bg.wasm) do echo   %%~zI bytes
) else (
    echo   N/A
)

echo No PQC:
if exist pkg\benchmarks\no-pqc\secure_cryptor_bg.wasm (
    for %%I in (pkg\benchmarks\no-pqc\secure_cryptor_bg.wasm) do echo   %%~zI bytes
) else (
    echo   N/A
)

echo Minimal:
if exist pkg\benchmarks\minimal\secure_cryptor_bg.wasm (
    for %%I in (pkg\benchmarks\minimal\secure_cryptor_bg.wasm) do echo   %%~zI bytes
) else (
    echo   N/A
)

echo.
echo ========================================
echo Build complete!
echo Results saved in pkg\benchmarks\
echo ========================================
