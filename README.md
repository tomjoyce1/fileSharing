# fileSharing

Secure, end- to-end encrypted file sharing platform

## MSYS2 setup (MinGW-w64, 64-bit)
1. Open the “MSYS2 MinGW 64-bit” shell and fully update the system.

2. Install the MinGW versions of: toolchain, CMake, Ninja (or Make), Qt 6
(base + Declarative + QuickControls2 + QuickDialogs2), Boost, OpenSSL,
libsodium, liboqs, and nlohmann-json.

3. All of these live under C:\msys64\mingw64, which matches the paths already
set in the project’s CMakeLists.txt.

## Build & run
1. Clone the repository and open a fresh MinGW 64-bit shell inside it.

2. Create a build folder, run CMake to configure, then build with Ninja or
Make.

3. Launch the generated qt_client.exe; running from the MinGW shell keeps all
required Qt and MinGW DLLs on the PATH.

4. Adjust src/config.h if you need to point the client at a different server
endpoint.

## Web client (React + Vite)

1. Use Node 18 or newer.

2. cd client/webapp/filestoragewebapp

3. npm install – installs all JS dependencies; if Vite later complains about a missing package, simply npm install <pkg>.

4. npm run dev – starts Vite on http://localhost:5173/.

5. Open that URL in the browser and log in / register as normal.

## Server (Bun)

1. Make sure Bun 1.x is installed.

2. cd server

3. Remove any previous local state: rm -rf drizzle TESTING_DB.sqlite

4. bun install – fetches dependencies.

5. bun run ./index.ts – launches the API on the configured port.
