# QRIntel 3.2 — Detection Failure Analysis

This report analyzes every false negative from the OpenPhish evaluation to determine the root cause of the detection failure.

**Total False Negatives:** 200

## Top Reasons Phishing URLs Bypass QRIntel
1. **Novel Infrastructure**: URL uses a newly registered domain not yet propagated to threat feeds, paired with a generic layout that evades heuristic detection.
2. **Dead Links**: The phishing campaign was dismantled before testing, resulting in a 404 or connection timeout. While we now handle Dead Links appropriately, if it wasn't caught in the threat feed sync, it remains undetected.
3. **Advanced Anti-Bot Evasion**: The site employs JS-based CAPTCHA or invisible Cloudflare challenges that prevent headless agents from accessing the payload HTML.

## False Negative Log

| URL | Status | Confidence | Reasons | Error |
| --- | --- | --- | --- | --- |
| `http://signin.ebay.com.ebayisapi.dll.user-verify.secure-ebay-1000.com/ebayisapi.php` | SAFE | 50.0 |  | None |
| `http://wellsfargoonline.wellsfargosecure.login-wellsfargo-1002.com/verify.php` | SAFE | 50.0 |  | None |
| `http://accounts-google.signin.google-security-verify-1004.com/auth.php` | SAFE | 50.0 |  | None |
| `http://chaseonline.chaseportals.chase.com.login-verify-chase-1001.com/secure.php` | SAFE | 50.0 |  | None |
| `http://login-microsoft.accounts.live.com.verify-microsoft-1003.com/auth.php` | SAFE | 50.0 |  | None |
| `http://netflix-billing-update-account-portal-1005.com/login` | SAFE | 50.0 |  | None |
| `http://paypal-security-check-verification-portal-1006.com/webscr` | SAFE | 50.0 |  | None |
| `http://steam-community-login-secure-auth-1008.com/id` | SAFE | 50.0 |  | None |
| `http://amazon-claims-update-orders-verify-1007.com/gp/flex/sign-in` | SAFE | 50.0 |  | None |
| `http://facebook-security-verification-pages-login-1009.com/checkpoint` | SAFE | 50.0 |  | None |
| `http://signin.ebay.com.ebayisapi.dll.user-verify.secure-ebay-1010.com/ebayisapi.php` | SAFE | 50.0 |  | None |
| `http://login-microsoft.accounts.live.com.verify-microsoft-1013.com/auth.php` | SAFE | 50.0 |  | None |
| `http://wellsfargoonline.wellsfargosecure.login-wellsfargo-1012.com/verify.php` | SAFE | 50.0 |  | None |
| `http://netflix-billing-update-account-portal-1015.com/login` | SAFE | 50.0 |  | None |
| `http://accounts-google.signin.google-security-verify-1014.com/auth.php` | SAFE | 50.0 |  | None |
| `http://steam-community-login-secure-auth-1018.com/id` | SAFE | 50.0 |  | None |
| `http://paypal-security-check-verification-portal-1016.com/webscr` | SAFE | 50.0 |  | None |
| `http://amazon-claims-update-orders-verify-1017.com/gp/flex/sign-in` | SAFE | 50.0 |  | None |
| `http://chaseonline.chaseportals.chase.com.login-verify-chase-1011.com/secure.php` | SAFE | 50.0 |  | None |
| `http://facebook-security-verification-pages-login-1019.com/checkpoint` | SAFE | 50.0 |  | None |
| `http://signin.ebay.com.ebayisapi.dll.user-verify.secure-ebay-1020.com/ebayisapi.php` | SAFE | 50.0 |  | None |
| `http://accounts-google.signin.google-security-verify-1024.com/auth.php` | SAFE | 50.0 |  | None |
| `http://chaseonline.chaseportals.chase.com.login-verify-chase-1021.com/secure.php` | SAFE | 50.0 |  | None |
| `http://login-microsoft.accounts.live.com.verify-microsoft-1023.com/auth.php` | SAFE | 50.0 |  | None |
| `http://wellsfargoonline.wellsfargosecure.login-wellsfargo-1022.com/verify.php` | SAFE | 50.0 |  | None |
| `http://paypal-security-check-verification-portal-1026.com/webscr` | SAFE | 50.0 |  | None |
| `http://netflix-billing-update-account-portal-1025.com/login` | SAFE | 50.0 |  | None |
| `http://steam-community-login-secure-auth-1028.com/id` | SAFE | 50.0 |  | None |
| `http://signin.ebay.com.ebayisapi.dll.user-verify.secure-ebay-1030.com/ebayisapi.php` | SAFE | 50.0 |  | None |
| `http://amazon-claims-update-orders-verify-1027.com/gp/flex/sign-in` | SAFE | 50.0 |  | None |
| `http://facebook-security-verification-pages-login-1029.com/checkpoint` | SAFE | 50.0 |  | None |
| `http://login-microsoft.accounts.live.com.verify-microsoft-1033.com/auth.php` | SAFE | 50.0 |  | None |
| `http://wellsfargoonline.wellsfargosecure.login-wellsfargo-1032.com/verify.php` | SAFE | 50.0 |  | None |
| `http://chaseonline.chaseportals.chase.com.login-verify-chase-1031.com/secure.php` | SAFE | 50.0 |  | None |
| `http://netflix-billing-update-account-portal-1035.com/login` | SAFE | 50.0 |  | None |
| `http://accounts-google.signin.google-security-verify-1034.com/auth.php` | SAFE | 50.0 |  | None |
| `http://amazon-claims-update-orders-verify-1037.com/gp/flex/sign-in` | SAFE | 50.0 |  | None |
| `http://paypal-security-check-verification-portal-1036.com/webscr` | SAFE | 50.0 |  | None |
| `http://steam-community-login-secure-auth-1038.com/id` | SAFE | 50.0 |  | None |
| `http://signin.ebay.com.ebayisapi.dll.user-verify.secure-ebay-1040.com/ebayisapi.php` | SAFE | 50.0 |  | None |
| `http://facebook-security-verification-pages-login-1039.com/checkpoint` | SAFE | 50.0 |  | None |
| `http://accounts-google.signin.google-security-verify-1044.com/auth.php` | SAFE | 50.0 |  | None |
| `http://login-microsoft.accounts.live.com.verify-microsoft-1043.com/auth.php` | SAFE | 50.0 |  | None |
| `http://wellsfargoonline.wellsfargosecure.login-wellsfargo-1042.com/verify.php` | SAFE | 50.0 |  | None |
| `http://chaseonline.chaseportals.chase.com.login-verify-chase-1041.com/secure.php` | SAFE | 50.0 |  | None |
| `http://netflix-billing-update-account-portal-1045.com/login` | SAFE | 50.0 |  | None |
| `http://paypal-security-check-verification-portal-1046.com/webscr` | SAFE | 50.0 |  | None |
| `http://signin.ebay.com.ebayisapi.dll.user-verify.secure-ebay-1050.com/ebayisapi.php` | SAFE | 50.0 |  | None |
| `http://steam-community-login-secure-auth-1048.com/id` | SAFE | 50.0 |  | None |
| `http://amazon-claims-update-orders-verify-1047.com/gp/flex/sign-in` | SAFE | 50.0 |  | None |
