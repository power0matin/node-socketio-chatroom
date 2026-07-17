# Changelog

All notable changes to this project will be documented in this file.

## [1.10.0] - 2026-07-17

### Security
- Added Content Security Policy (CSP) allowing only trusted CDN sources
- Added Origin/Referer header validation on upload endpoint (CSRF protection)
- Added IP-based login rate limiting (30 attempts/10min per IP)
- Added channel name validation to reject reserved names (`_pv_`, `__saved__`)
- Added SRI integrity hashes for Vue.js and FontAwesome CDN resources
- Improved `json_escape` in installer to handle control characters

### Fixed
- Removed duplicate `/uploads` static middleware
- Fixed DM message history limit (now 500, was 100)
- Fixed auto-rejoin channel after network reconnect
- Fixed scroll-to-bottom behavior (only scrolls when near bottom)
- Fixed scroll listener attachment for dynamic DOM
- Added Socket.IO connection error handling
- Fixed `maxHttpBufferSize` alignment between repo and installer
- Added graceful shutdown handlers (SIGTERM/SIGINT)
- Added `pb-28` padding to installer's messages container
- Removed `user-scalable=no` from installer's viewport meta
- Fixed README to use `npm start` instead of `node server.js`

### Added
- SVG favicon for chat application
- Configurable message history limits (`maxChannelMessages`, `maxDmMessages`, `maxSavedMessages`)
- Default channel auto-join for new users (`defaultChannelsForNewUsers: ["General"]`)
- `fs.watch()` for faster config hot-reload
- Dirty tracking for `saveData()` (skips writes when no changes)
- Reduced save interval from 30s to 10s
- Audio recording now uploads via `/upload` endpoint (no more WebSocket data URLs)
- Bash version check in installer
- Backup failure warning in installer
- Dynamic APP_NAME detection in menu.sh
- Configurable message limits in admin settings
- CHANGELOG.md

### Changed
- Default CORS origin changed from `*` to `http://localhost:3000`
- Default `defaultChannelsForNewUsers` changed from `[]` to `["General"]`
- Audio recordings uploaded via HTTP instead of WebSocket

## [1.1.18] - Previous release

Initial documented version.
