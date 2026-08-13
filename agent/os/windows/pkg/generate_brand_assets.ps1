param(
    [string] $SourcePng = (Join-Path $PSScriptRoot "assets\attacklens-logo-256.png")
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$assetsDir = Join-Path $PSScriptRoot "assets"
$iconPath = Join-Path $assetsDir "attacklens.ico"
$bannerPath = Join-Path $assetsDir "installer-banner.bmp"
$dialogPath = Join-Path $assetsDir "installer-dialog.bmp"

if (-not (Test-Path -LiteralPath $SourcePng -PathType Leaf)) {
    throw "Source PNG not found: $SourcePng"
}

function New-ResizedPngBytes {
    param(
        [Parameter(Mandatory = $true)]
        [System.Drawing.Image] $Source,

        [Parameter(Mandatory = $true)]
        [int] $Size
    )

    $bitmap = New-Object System.Drawing.Bitmap(
        $Size,
        $Size,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
    )
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $stream = New-Object System.IO.MemoryStream
    try {
        $graphics.Clear([System.Drawing.Color]::Transparent)
        $graphics.CompositingMode =
            [System.Drawing.Drawing2D.CompositingMode]::SourceOver
        $graphics.CompositingQuality =
            [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $graphics.InterpolationMode =
            [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.PixelOffsetMode =
            [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $graphics.SmoothingMode =
            [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.DrawImage(
            $Source,
            (New-Object System.Drawing.Rectangle(0, 0, $Size, $Size))
        )
        $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
        return $stream.ToArray()
    } finally {
        $stream.Dispose()
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

function Write-MultiResolutionIcon {
    param(
        [Parameter(Mandatory = $true)]
        [System.Drawing.Image] $Source,

        [Parameter(Mandatory = $true)]
        [string] $OutputPath
    )

    $sizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
    $frames = foreach ($size in $sizes) {
        [pscustomobject]@{
            Size = $size
            Data = [byte[]](New-ResizedPngBytes -Source $Source -Size $size)
        }
    }

    $stream = [System.IO.File]::Open(
        $OutputPath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    $writer = New-Object System.IO.BinaryWriter($stream)
    try {
        $writer.Write([uint16]0)
        $writer.Write([uint16]1)
        $writer.Write([uint16]$frames.Count)

        $offset = 6 + (16 * $frames.Count)
        foreach ($frame in $frames) {
            $dimension = if ($frame.Size -eq 256) { 0 } else { $frame.Size }
            $writer.Write([byte]$dimension)
            $writer.Write([byte]$dimension)
            $writer.Write([byte]0)
            $writer.Write([byte]0)
            $writer.Write([uint16]1)
            $writer.Write([uint16]32)
            $writer.Write([uint32]$frame.Data.Length)
            $writer.Write([uint32]$offset)
            $offset += $frame.Data.Length
        }

        foreach ($frame in $frames) {
            $writer.Write([byte[]]$frame.Data)
        }
    } finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

function Write-InstallerBanner {
    param(
        [Parameter(Mandatory = $true)]
        [System.Drawing.Image] $Logo,

        [Parameter(Mandatory = $true)]
        [string] $OutputPath
    )

    $bitmap = New-Object System.Drawing.Bitmap(
        493,
        58,
        [System.Drawing.Imaging.PixelFormat]::Format24bppRgb
    )
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $accent = New-Object System.Drawing.SolidBrush(
        [System.Drawing.ColorTranslator]::FromHtml("#7326D3")
    )
    try {
        $graphics.Clear([System.Drawing.Color]::White)
        $graphics.FillRectangle($accent, 0, 54, 493, 4)
        $graphics.InterpolationMode =
            [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode =
            [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.DrawImage(
            $Logo,
            (New-Object System.Drawing.Rectangle(438, 4, 50, 50))
        )
        $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
    } finally {
        $accent.Dispose()
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

function Write-InstallerDialog {
    param(
        [Parameter(Mandatory = $true)]
        [System.Drawing.Image] $Logo,

        [Parameter(Mandatory = $true)]
        [string] $OutputPath
    )

    $bitmap = New-Object System.Drawing.Bitmap(
        493,
        312,
        [System.Drawing.Imaging.PixelFormat]::Format24bppRgb
    )
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $sidebar = New-Object System.Drawing.Rectangle(0, 0, 164, 312)
    $gradient = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $sidebar,
        [System.Drawing.ColorTranslator]::FromHtml("#35105F"),
        [System.Drawing.ColorTranslator]::FromHtml("#8238E8"),
        90.0
    )
    $white = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $muted = New-Object System.Drawing.SolidBrush(
        [System.Drawing.ColorTranslator]::FromHtml("#E9DBFF")
    )
    $titleFont = New-Object System.Drawing.Font(
        "Segoe UI",
        19,
        [System.Drawing.FontStyle]::Bold,
        [System.Drawing.GraphicsUnit]::Point
    )
    $subtitleFont = New-Object System.Drawing.Font(
        "Segoe UI",
        9,
        [System.Drawing.FontStyle]::Regular,
        [System.Drawing.GraphicsUnit]::Point
    )
    try {
        $graphics.Clear([System.Drawing.Color]::White)
        $graphics.FillRectangle($gradient, $sidebar)
        $graphics.InterpolationMode =
            [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode =
            [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.DrawImage(
            $Logo,
            (New-Object System.Drawing.Rectangle(27, 34, 110, 110))
        )
        $graphics.DrawString("AttackLens", $titleFont, $white, 18, 170)
        $graphics.DrawString(
            "ENDPOINT AGENT",
            $subtitleFont,
            $muted,
            35,
            212
        )
        $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
    } finally {
        $subtitleFont.Dispose()
        $titleFont.Dispose()
        $muted.Dispose()
        $white.Dispose()
        $gradient.Dispose()
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

$source = [System.Drawing.Image]::FromFile($SourcePng)
try {
    Write-MultiResolutionIcon -Source $source -OutputPath $iconPath
    Write-InstallerBanner -Logo $source -OutputPath $bannerPath
    Write-InstallerDialog -Logo $source -OutputPath $dialogPath
} finally {
    $source.Dispose()
}

Get-Item -LiteralPath $iconPath, $bannerPath, $dialogPath |
    Select-Object FullName, Length, LastWriteTime
