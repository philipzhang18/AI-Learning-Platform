# Changelog for CVE Security Solution

## [Fixed] - 2025-10-30

### Fixed
- Made API endpoints configurable in web interfaces (cve_web_interface.html and cve_web_interface_v2.html)
- Added getApiConfig() function to allow API URL configuration via URL parameters or localStorage
- Improved error handling in web interfaces with more informative messages
- Enhanced file path handling in run.py with better exception handling
- Fixed potential file path issues in data directory opening

### Changed
- Both web interfaces now support configurable API endpoints instead of hardcoded localhost
- Better error messages when API server is unavailable
- More robust file path handling in launcher script

### Added
- getApiConfig() function in both web interfaces for dynamic API configuration
- Exception handling for directory operations in run.py
- Test script to verify all changes