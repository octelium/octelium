#!/bin/bash

set -e

PACKAGE_NAME=""
VERSION=""
ARCH=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --package-name)
      PACKAGE_NAME="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --arch)
      ARCH="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [ -z "$PACKAGE_NAME" ] || [ -z "$VERSION" ] || [ -z "$ARCH" ]; then
  echo "Usage: $0 --package-name <name> --version <version> --arch <arch>"
  exit 1
fi

echo "Building PKG for $PACKAGE_NAME version $VERSION ($ARCH)"

if [ "$ARCH" = "amd64" ]; then
  PKG_ARCH="x86_64"
elif [ "$ARCH" = "arm64" ]; then
  PKG_ARCH="arm64"
else
  echo "Unknown architecture: $ARCH"
  exit 1
fi

PACKAGE_ID="com.octelium.${PACKAGE_NAME}"

case $PACKAGE_NAME in
  octelium)
    DESCRIPTION="Octelium - Zero trust secure access platform with VPN, ZTNA, and API gateway capabilities"
    ;;
  octeliumctl)
    DESCRIPTION="Octeliumctl - Control and management CLI for Octelium"
    ;;
  octops)
    DESCRIPTION="Octops - Operations and administration tool for Octelium"
    ;;
  *)
    DESCRIPTION="$PACKAGE_NAME - Octelium suite component"
    ;;
esac

PKG_ROOT="packaging/pkg-root/$PACKAGE_NAME"
SCRIPTS_DIR="packaging/pkg-scripts/$PACKAGE_NAME"
OUTPUT_DIR="packaging"

mkdir -p "$PKG_ROOT/usr/local/bin"
mkdir -p "$SCRIPTS_DIR"
mkdir -p "$OUTPUT_DIR"

cp "bin/$PACKAGE_NAME" "$PKG_ROOT/usr/local/bin/"
chmod +x "$PKG_ROOT/usr/local/bin/$PACKAGE_NAME"

cat > "$SCRIPTS_DIR/postinstall" <<'EOF'
#!/bin/bash

add_to_path() {
    local profile_file="$1"
    
    if [ -f "$profile_file" ]; then
        if ! grep -q '/usr/local/bin' "$profile_file"; then
            echo 'export PATH="/usr/local/bin:$PATH"' >> "$profile_file"
            echo "Added /usr/local/bin to PATH in $profile_file"
        fi
    fi
}

for user_home in /Users/*; do
    if [ -d "$user_home" ]; then
        username=$(basename "$user_home")
        
        if [ "$username" = "Shared" ] || [ "$username" = "Guest" ]; then
            continue
        fi
        
        add_to_path "$user_home/.zshrc"
        add_to_path "$user_home/.bash_profile"
        add_to_path "$user_home/.bashrc"
    fi
done

exit 0
EOF

chmod +x "$SCRIPTS_DIR/postinstall"

DIST_XML="packaging/distribution-$PACKAGE_NAME.xml"
cat > "$DIST_XML" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>$PACKAGE_NAME</title>
    <organization>com.octelium</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="false" hostArchitectures="$PKG_ARCH"/>
    
    <welcome file="welcome.html" mime-type="text/html" />
    <license file="LICENSE-APACHE" mime-type="text/plain" />
    <conclusion file="conclusion.html" mime-type="text/html" />
    
    <pkg-ref id="$PACKAGE_ID"/>
    
    <options customize="never" require-scripts="true"/>
    
    <choices-outline>
        <line choice="default">
            <line choice="$PACKAGE_ID"/>
        </line>
    </choices-outline>
    
    <choice id="default"/>
    
    <choice id="$PACKAGE_ID" visible="false">
        <pkg-ref id="$PACKAGE_ID"/>
    </choice>
    
    <pkg-ref id="$PACKAGE_ID" version="$VERSION" onConclusion="none">
        ${PACKAGE_NAME}-component.pkg
    </pkg-ref>
</installer-gui-script>
EOF

cat > "packaging/welcome.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>Welcome to $PACKAGE_NAME Installer</h1>
    <p>$DESCRIPTION</p>
    <p>This installer will install $PACKAGE_NAME version $VERSION on your system.</p>
    <p>The binary will be installed to <strong>/usr/local/bin</strong> and will be available in your PATH.</p>
</body>
</html>
EOF

cat > "packaging/conclusion.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
        h1 { color: #333; }
        code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Installation Complete</h1>
    <p>$PACKAGE_NAME has been successfully installed!</p>
    <p>You can now use it by running: <code>$PACKAGE_NAME</code></p>
    <p>You may need to restart your terminal or run <code>source ~/.zshrc</code> for PATH changes to take effect.</p>
</body>
</html>
EOF

cp LICENSE-APACHE packaging/

echo "Building component package..."
pkgbuild \
  --root "$PKG_ROOT" \
  --identifier "$PACKAGE_ID" \
  --version "$VERSION" \
  --scripts "$SCRIPTS_DIR" \
  --install-location / \
  "packaging/${PACKAGE_NAME}-component.pkg"

echo "Building product package..."
productbuild \
  --distribution "$DIST_XML" \
  --resources "packaging" \
  --package-path "packaging" \
  --version "$VERSION" \
  "$OUTPUT_DIR/${PACKAGE_NAME}-${VERSION}-${ARCH}.pkg"

rm -f "packaging/${PACKAGE_NAME}-component.pkg"
rm -f "$DIST_XML"
rm -f "packaging/welcome.html"
rm -f "packaging/conclusion.html"
rm -f "packaging/LICENSE-APACHE"

echo "Successfully created: $OUTPUT_DIR/${PACKAGE_NAME}-${VERSION}-${ARCH}.pkg"