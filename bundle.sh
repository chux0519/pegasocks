#! /bin/bash
app_path=build/pegas.app/Contents
bin_path="$app_path/MacOS"

CreateApp() {
  rm -rf build/pegas.app
  mkdir -p $bin_path && cp build/pegas $bin_path/_pegas
  echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>English</string>
    <key>CFBundleExecutable</key>
    <string>start_pegas</string>
    <key>CFBundleGetInfoString</key>
    <string>pegasocks 0.0.0</string>
    <key>CFBundleIconFile</key>
    <string>pegas.icns</string>
    <key>CFBundleIdentifier</key>
    <string>org.hexyoungs.club</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>pegas</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0</string>
    <key>CFBundleSignature</key>
    <string>hexyoungs.club</string>
    <key>CFBundleVersion</key>
    <string>0.0.0</string>
    <key>NSAppleScriptEnabled</key>
    <string>YES</string>
</dict>
</plist>
" > "$app_path/Info.plist" && \
  echo "APPLPEGAS" > "$app_path/PkgInfo" && \
  echo "#!/bin/bash
cd \"\${0%/*}\"
./_pegas -c ~/.pegasrc
" > $bin_path/start_pegas && \
  chmod +x $bin_path/start_pegas
}

CreateIcns() {
  mkdir pegas.iconset
  sips -z 16 16     ./iconx1024.png --out pegas.iconset/icon_16x16.png
  sips -z 32 32     ./iconx1024.png --out pegas.iconset/icon_16x16@2x.png
  sips -z 32 32     ./iconx1024.png --out pegas.iconset/icon_32x32.png
  sips -z 64 64     ./iconx1024.png --out pegas.iconset/icon_32x32@2x.png
  sips -z 128 128   ./iconx1024.png --out pegas.iconset/icon_128x128.png
  sips -z 256 256   ./iconx1024.png --out pegas.iconset/icon_128x128@2x.png
  sips -z 256 256   ./iconx1024.png --out pegas.iconset/icon_256x256.png
  sips -z 512 512   ./iconx1024.png --out pegas.iconset/icon_256x256@2x.png
  sips -z 512 512   ./iconx1024.png --out pegas.iconset/icon_512x512.png
  cp iconx1024.png pegas.iconset/icon_512x512@2x.png
  iconutil -c icns pegas.iconset
  rm -R pegas.iconset
  mkdir "$app_path/Resources" && mv pegas.icns "$app_path/Resources" && cp ./icon.png $app_path/Resources
}

CopyDll() {
  dlls=($(otool -L "$bin_path/_pegas" | grep local | cut -d " " -f 1))
  for dll in "${dlls[@]}";
  do
      lib_name=($(basename $dll))
      echo copying $lib_name
      cp $dll $bin_path
      install_name_tool -change $dll @executable_path/$lib_name $bin_path/_pegas
  done
}

CreateApp && \
CreateIcns && \
CopyDll
