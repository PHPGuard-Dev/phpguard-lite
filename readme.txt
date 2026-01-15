=== PHPGuard Lite ===
Contributors: mwouterse
Tags: security, wsod, syntax, errors, developer
Requires at least: 5.5
Tested up to: 6.9
Requires PHP: 7.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Check WordPress plugins and PHP code for syntax errors before activating or using them.

== Description ==

PHPGuard Lite helps prevent white screens and fatal errors by allowing you to scan WordPress plugins and PHP code for syntax issues before they are activated or used.

It provides three main tools:

* Scan installed plugins for PHP syntax errors  
* Scan a plugin ZIP file before installing it  
* Scan pasted PHP code snippets  

All scans run locally on your server. No code is executed. No data leaves your site.

The plugin uses a safe, non-executing PHP parser to detect parse errors and fatal syntax issues that would otherwise crash WordPress when a plugin or snippet is loaded.

=== Privacy & Security ===

PHPGuard Lite is fully self-contained.

* No telemetry  
* No accounts  
* No email collection  
* No licensing calls  
* No remote servers  
* No background connections  

All scanning is done locally on your WordPress installation.

=== About base64 in snippet scanning ===

When scanning pasted code snippets, the browser may send the code using base64 encoding. This is only used to safely transport pasted text through an HTTP request without breaking due to special characters or encoding issues.

The base64 data is immediately decoded back into plain text and passed to the PHP parser. The code is never executed, stored, or sent anywhere.

This is a transport mechanism only — not obfuscation, encryption, or remote communication.

=== PHPGuard Pro ===

An optional commercial version, PHPGuard Pro, is planned. It will provide advanced automation and safety features for professional and agency workflows. Information about PHPGuard Pro is available on the project website.

== Installation ==

1. Upload the plugin ZIP through Plugins → Add New → Upload Plugin
2. Activate PHPGuard Lite
3. Open PHPGuard from the WordPress admin menu

== Usage ==

After activation, open PHPGuard in the WordPress admin menu.

You can:

* Select an installed plugin and run a syntax scan
* Upload a plugin ZIP and scan it before installation
* Paste PHP code into the snippet scanner

Results will show any detected syntax errors or potential issues.

== Frequently Asked Questions ==

= Does PHPGuard execute the code being scanned? =
No. PHPGuard uses a safe PHP parser that reads code without executing it.

= Does PHPGuard send anything to external servers? =
No. All scans run locally. No data is sent anywhere.

= Why do I see base64 in the code? =
It is used only to safely transmit pasted code through HTTP without breaking on special characters. The data is decoded locally and scanned.

== Changelog ==

= 1.0.0 =
* Initial public release

== Support ==

Documentation and project updates are available on the PHPGuard website.
