#!/usr/bin/python
# -*- coding: utf-8 -*-
import argparse
import sqlite3 as lite
import sys
import requests
import uuid
import re
import time
from xml.dom import minidom
from xml.etree import ElementTree as ET
import datetime

# current CWE LIST for CWE matching. If an match is found, it is used. 
# If no match is found, it uses 16 by default 
cwes ={
       "1": "Location",
"2": "Environment",
"3": "Technology-specific Environment Issues",
"4": "J2EE Environment Issues",
"5": "J2EE Misconfiguration: Data Transmission Without Encryption",
"6": "J2EE Misconfiguration: Insufficient Session-ID Length",
"7": "J2EE Misconfiguration: Missing Custom Error Page",
"8": "J2EE Misconfiguration: Entity Bean Declared Remote",
"9": "J2EE Misconfiguration: Weak Access Permissions for EJB Methods",
"10": "ASP.NET Environment Issues",
"11": "ASP.NET Misconfiguration: Creating Debug Binary",
"12": "ASP.NET Misconfiguration: Missing Custom Error Page",
"13": "ASP.NET Misconfiguration: Password in Configuration File",
"14": "Compiler Removal of Code to Clear Buffers",
"15": "External Control of System or Configuration Setting",
"16": "Configuration",
"17": "Code",
"18": "Source Code",
"19": "Data Handling",
"20": "Improper Input Validation",
"21": "Pathname Traversal and Equivalence Errors",
"22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
"23": "Relative Path Traversal",
"24": "Path Traversal: '../filedir'",
"25": "Path Traversal: '/../filedir'",
"26": "Path Traversal: '/dir/../filename'",
"27": "Path Traversal: 'dir/../../filename'",
"28": "Path Traversal: '..\\filedir'",
"29": "Path Traversal: '\\..\\filename'",
"30": "Path Traversal: '\\dir\\..\\filename'",
"31": "Path Traversal: 'dir\\..\\..\\filename'",
"32": "Path Traversal: '...' (Triple Dot)",
"33": "Path Traversal: '....' (Multiple Dot)",
"34": "Path Traversal: '....//'",
"35": "Path Traversal: '.../...//'",
"36": "Absolute Path Traversal",
"37": "Path Traversal: '/absolute/pathname/here'",
"38": "Path Traversal: '\\absolute\\pathname\\here'",
"39": "Path Traversal: 'C:dirname'",
"40": "Path Traversal: '\\\\UNC\\share\\name\\' (Windows UNC Share)",
"41": "Improper Resolution of Path Equivalence",
"42": "Path Equivalence: 'filename.' (Trailing Dot)",
"43": "Path Equivalence: 'filename....' (Multiple Trailing Dot)",
"44": "Path Equivalence: 'file.name' (Internal Dot)",
"45": "Path Equivalence: 'file...name' (Multiple Internal Dot)",
"46": "Path Equivalence: 'filename ' (Trailing Space)",
"47": "Path Equivalence: ' filename' (Leading Space)",
"48": "Path Equivalence: 'file name' (Internal Whitespace)",
"49": "Path Equivalence: 'filename/' (Trailing Slash)",
"50": "Path Equivalence: '//multiple/leading/slash'",
"51": "Path Equivalence: '/multiple//internal/slash'",
"52": "Path Equivalence: '/multiple/trailing/slash//'",
"53": "Path Equivalence: '\\multiple\\\\internal\\backslash'",
"54": "Path Equivalence: 'filedir\\' (Trailing Backslash)",
"55": "Path Equivalence: '/./' (Single Dot Directory)",
"56": "Path Equivalence: 'filedir*' (Wildcard)",
"57": "Path Equivalence: 'fakedir/../realdir/filename'",
"58": "Path Equivalence: Windows 8.3 Filename",
"59": "Improper Link Resolution Before File Access ('Link Following')",
"60": "UNIX Path Link Problems",
"61": "UNIX Symbolic Link (Symlink) Following",
"62": "UNIX Hard Link",
"63": "Windows Path Link Problems",
"64": "Windows Shortcut Following (.LNK)",
"65": "Windows Hard Link",
"66": "Improper Handling of File Names that Identify Virtual Resources",
"67": "Improper Handling of Windows Device Names",
"68": "Windows Virtual File Problems",
"69": "Improper Handling of Windows ::DATA Alternate Data Stream",
"70": "Mac Virtual File Problems",
"71": "Apple '.DS_Store'",
"72": "Improper Handling of Apple HFS+ Alternate Data Stream Path",
"73": "External Control of File Name or Path",
"74": "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
"75": "Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)",
"76": "Improper Neutralization of Equivalent Special Elements",
"77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
"78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
"79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
"80": "Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)",
"81": "Improper Neutralization of Script in an Error Message Web Page",
"82": "Improper Neutralization of Script in Attributes of IMG Tags in a Web Page",
"83": "Improper Neutralization of Script in Attributes in a Web Page",
"84": "Improper Neutralization of Encoded URI Schemes in a Web Page",
"85": "Doubled Character XSS Manipulations",
"86": "Improper Neutralization of Invalid Characters in Identifiers in Web Pages",
"87": "Improper Neutralization of Alternate XSS Syntax",
"88": "Argument Injection or Modification",
"89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
"90": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
"91": "XML Injection (aka Blind XPath Injection)",
"92": "DEPRECATED: Improper Sanitization of Custom Special Characters",
"93": "Improper Neutralization of CRLF Sequences ('CRLF Injection')",
"94": "Improper Control of Generation of Code ('Code Injection')",
"95": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
"96": "Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')",
"97": "Improper Neutralization of Server-Side Includes (SSI) Within a Web Page",
"98": "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')",
"99": "Improper Control of Resource Identifiers ('Resource Injection')",
"100": "Technology-Specific Input Validation Problems",
"101": "Struts Validation Problems",
"102": "Struts: Duplicate Validation Forms",
"103": "Struts: Incomplete validate() Method Definition",
"104": "Struts: Form Bean Does Not Extend Validation Class",
"105": "Struts: Form Field Without Validator",
"106": "Struts: Plug-in Framework not in Use",
"107": "Struts: Unused Validation Form",
"108": "Struts: Unvalidated Action Form",
"109": "Struts: Validator Turned Off",
"110": "Struts: Validator Without Form Field",
"111": "Direct Use of Unsafe JNI",
"112": "Missing XML Validation",
"113": "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
"114": "Process Control",
"115": "Misinterpretation of Input",
"116": "Improper Encoding or Escaping of Output",
"117": "Improper Output Neutralization for Logs",
"118": "Improper Access of Indexable Resource ('Range Error')",
"119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
"120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
"121": "Stack-based Buffer Overflow",
"122": "Heap-based Buffer Overflow",
"123": "Write-what-where Condition",
"124": "Buffer Underwrite ('Buffer Underflow')",
"125": "Out-of-bounds Read",
"126": "Buffer Over-read",
"127": "Buffer Under-read",
"128": "Wrap-around Error",
"129": "Improper Validation of Array Index",
"130": "Improper Handling of Length Parameter Inconsistency ",
"131": "Incorrect Calculation of Buffer Size",
"132": "DEPRECATED (Duplicate): Miscalculated Null Termination",
"133": "String Errors",
"134": "Uncontrolled Format String",
"135": "Incorrect Calculation of Multi-Byte String Length",
"136": "Type Errors",
"137": "Representation Errors",
"138": "Improper Neutralization of Special Elements",
"139": "DEPRECATED: General Special Element Problems",
"140": "Improper Neutralization of Delimiters",
"141": "Improper Neutralization of Parameter/Argument Delimiters",
"142": "Improper Neutralization of Value Delimiters",
"143": "Improper Neutralization of Record Delimiters",
"144": "Improper Neutralization of Line Delimiters",
"145": "Improper Neutralization of Section Delimiters",
"146": "Improper Neutralization of Expression/Command Delimiters",
"147": "Improper Neutralization of Input Terminators",
"148": "Improper Neutralization of Input Leaders",
"149": "Improper Neutralization of Quoting Syntax",
"150": "Improper Neutralization of Escape, Meta, or Control Sequences",
"151": "Improper Neutralization of Comment Delimiters",
"152": "Improper Neutralization of Macro Symbols",
"153": "Improper Neutralization of Substitution Characters",
"154": "Improper Neutralization of Variable Name Delimiters",
"155": "Improper Neutralization of Wildcards or Matching Symbols",
"156": "Improper Neutralization of Whitespace",
"157": "Failure to Sanitize Paired Delimiters",
"158": "Improper Neutralization of Null Byte or NUL Character",
"159": "Failure to Sanitize Special Element",
"160": "Improper Neutralization of Leading Special Elements",
"161": "Improper Neutralization of Multiple Leading Special Elements",
"162": "Improper Neutralization of Trailing Special Elements",
"163": "Improper Neutralization of Multiple Trailing Special Elements",
"164": "Improper Neutralization of Internal Special Elements",
"165": "Improper Neutralization of Multiple Internal Special Elements",
"166": "Improper Handling of Missing Special Element",
"167": "Improper Handling of Additional Special Element",
"168": "Improper Handling of Inconsistent Special Elements",
"169": "Technology-Specific Special Elements",
"170": "Improper Null Termination",
"171": "Cleansing, Canonicalization, and Comparison Errors",
"172": "Encoding Error",
"173": "Improper Handling of Alternate Encoding",
"174": "Double Decoding of the Same Data",
"175": "Improper Handling of Mixed Encoding",
"176": "Improper Handling of Unicode Encoding",
"177": "Improper Handling of URL Encoding (Hex Encoding)",
"178": "Improper Handling of Case Sensitivity",
"179": "Incorrect Behavior Order: Early Validation",
"180": "Incorrect Behavior Order: Validate Before Canonicalize",
"181": "Incorrect Behavior Order: Validate Before Filter",
"182": "Collapse of Data into Unsafe Value",
"183": "Permissive Whitelist",
"184": "Incomplete Blacklist",
"185": "Incorrect Regular Expression",
"186": "Overly Restrictive Regular Expression",
"187": "Partial Comparison",
"188": "Reliance on Data/Memory Layout",
"189": "Numeric Errors",
"190": "Integer Overflow or Wraparound",
"191": "Integer Underflow (Wrap or Wraparound)",
"192": "Integer Coercion Error",
"193": "Off-by-one Error",
"194": "Unexpected Sign Extension",
"195": "Signed to Unsigned Conversion Error",
"196": "Unsigned to Signed Conversion Error",
"197": "Numeric Truncation Error",
"198": "Use of Incorrect Byte Ordering",
"199": "Information Management Errors",
"200": "Information Exposure",
"201": "Information Exposure Through Sent Data",
"202": "Exposure of Sensitive Data Through Data Queries",
"203": "Information Exposure Through Discrepancy",
"204": "Response Discrepancy Information Exposure",
"205": "Information Exposure Through Behavioral Discrepancy",
"206": "Information Exposure of Internal State Through Behavioral Inconsistency",
"207": "Information Exposure Through an External Behavioral Inconsistency",
"208": "Information Exposure Through Timing Discrepancy",
"209": "Information Exposure Through an Error Message",
"210": "Information Exposure Through Self-generated Error Message",
"211": "Information Exposure Through Externally-generated Error Message",
"212": "Improper Cross-boundary Removal of Sensitive Data",
"213": "Intentional Information Exposure",
"214": "Information Exposure Through Process Environment",
"215": "Information Exposure Through Debug Information",
"216": "Containment Errors (Container Errors)",
"217": "DEPRECATED: Failure to Protect Stored Data from Modification",
"218": "DEPRECATED (Duplicate): Failure to provide confidentiality for stored data",
"219": "Sensitive Data Under Web Root",
"220": "Sensitive Data Under FTP Root",
"221": "Information Loss or Omission",
"222": "Truncation of Security-relevant Information",
"223": "Omission of Security-relevant Information",
"224": "Obscured Security-relevant Information by Alternate Name",
"225": "DEPRECATED (Duplicate): General Information Management Problems",
"226": "Sensitive Information Uncleared Before Release",
"227": "Improper Fulfillment of API Contract ('API Abuse')",
"228": "Improper Handling of Syntactically Invalid Structure",
"229": "Improper Handling of Values",
"230": "Improper Handling of Missing Values",
"231": "Improper Handling of Extra Values",
"232": "Improper Handling of Undefined Values",
"233": "Improper Handling of Parameters",
"234": "Failure to Handle Missing Parameter",
"235": "Improper Handling of Extra Parameters",
"236": "Improper Handling of Undefined Parameters",
"237": "Improper Handling of Structural Elements",
"238": "Improper Handling of Incomplete Structural Elements",
"239": "Failure to Handle Incomplete Element",
"240": "Improper Handling of Inconsistent Structural Elements",
"241": "Improper Handling of Unexpected Data Type",
"242": "Use of Inherently Dangerous Function",
"243": "Creation of chroot Jail Without Changing Working Directory",
"244": "Improper Clearing of Heap Memory Before Release ('Heap Inspection')",
"245": "J2EE Bad Practices: Direct Management of Connections",
"246": "J2EE Bad Practices: Direct Use of Sockets",
"247": "DEPRECATED (Duplicate): Reliance on DNS Lookups in a Security Decision",
"248": "Uncaught Exception",
"249": "DEPRECATED: Often Misused: Path Manipulation",
"250": "Execution with Unnecessary Privileges",
"251": "Often Misused: String Management",
"252": "Unchecked Return Value",
"253": "Incorrect Check of Function Return Value",
"254": "Security Features",
"255": "Credentials Management",
"256": "Plaintext Storage of a Password",
"257": "Storing Passwords in a Recoverable Format",
"258": "Empty Password in Configuration File",
"259": "Use of Hard-coded Password",
"260": "Password in Configuration File",
"261": "Weak Cryptography for Passwords",
"262": "Not Using Password Aging",
"263": "Password Aging with Long Expiration",
"264": "Permissions, Privileges, and Access Controls",
"265": "Privilege / Sandbox Issues",
"266": "Incorrect Privilege Assignment",
"267": "Privilege Defined With Unsafe Actions",
"268": "Privilege Chaining",
"269": "Improper Privilege Management",
"270": "Privilege Context Switching Error",
"271": "Privilege Dropping / Lowering Errors",
"272": "Least Privilege Violation",
"273": "Improper Check for Dropped Privileges",
"274": "Improper Handling of Insufficient Privileges",
"275": "Permission Issues",
"276": "Incorrect Default Permissions",
"277": "Insecure Inherited Permissions",
"278": "Insecure Preserved Inherited Permissions",
"279": "Incorrect Execution-Assigned Permissions",
"280": "Improper Handling of Insufficient Permissions or Privileges ",
"281": "Improper Preservation of Permissions",
"282": "Improper Ownership Management",
"283": "Unverified Ownership",
"284": "Improper Access Control",
"285": "Improper Authorization",
"286": "Incorrect User Management",
"287": "Improper Authentication",
"288": "Authentication Bypass Using an Alternate Path or Channel",
"289": "Authentication Bypass by Alternate Name",
"290": "Authentication Bypass by Spoofing",
"291": "Reliance on IP Address for Authentication",
"292": "DEPRECATED (Duplicate): Trusting Self-reported DNS Name",
"293": "Using Referer Field for Authentication",
"294": "Authentication Bypass by Capture-replay",
"295": "Improper Certificate Validation",
"296": "Improper Following of a Certificate's Chain of Trust",
"297": "Improper Validation of Certificate with Host Mismatch",
"298": "Improper Validation of Certificate Expiration",
"299": "Improper Check for Certificate Revocation",
"300": "Channel Accessible by Non-Endpoint ('Man-in-the-Middle')",
"301": "Reflection Attack in an Authentication Protocol",
"302": "Authentication Bypass by Assumed-Immutable Data",
"303": "Incorrect Implementation of Authentication Algorithm",
"304": "Missing Critical Step in Authentication",
"305": "Authentication Bypass by Primary Weakness",
"306": "Missing Authentication for Critical Function",
"307": "Improper Restriction of Excessive Authentication Attempts",
"308": "Use of Single-factor Authentication",
"309": "Use of Password System for Primary Authentication",
"310": "Cryptographic Issues",
"311": "Missing Encryption of Sensitive Data",
"312": "Cleartext Storage of Sensitive Information",
"313": "Cleartext Storage in a File or on Disk",
"314": "Cleartext Storage in the Registry",
"315": "Cleartext Storage of Sensitive Information in a Cookie",
"316": "Cleartext Storage of Sensitive Information in Memory",
"317": "Cleartext Storage of Sensitive Information in GUI",
"318": "Cleartext Storage of Sensitive Information in Executable",
"319": "Cleartext Transmission of Sensitive Information",
"320": "Key Management Errors",
"321": "Use of Hard-coded Cryptographic Key",
"322": "Key Exchange without Entity Authentication",
"323": "Reusing a Nonce, Key Pair in Encryption",
"324": "Use of a Key Past its Expiration Date",
"325": "Missing Required Cryptographic Step",
"326": "Inadequate Encryption Strength",
"327": "Use of a Broken or Risky Cryptographic Algorithm",
"328": "Reversible One-Way Hash",
"329": "Not Using a Random IV with CBC Mode",
"330": "Use of Insufficiently Random Values",
"331": "Insufficient Entropy",
"332": "Insufficient Entropy in PRNG",
"333": "Improper Handling of Insufficient Entropy in TRNG",
"334": "Small Space of Random Values",
"335": "PRNG Seed Error",
"336": "Same Seed in PRNG",
"337": "Predictable Seed in PRNG",
"338": "Use of Cryptographically Weak PRNG",
"339": "Small Seed Space in PRNG",
"340": "Predictability Problems",
"341": "Predictable from Observable State",
"342": "Predictable Exact Value from Previous Values",
"343": "Predictable Value Range from Previous Values",
"344": "Use of Invariant Value in Dynamically Changing Context",
"345": "Insufficient Verification of Data Authenticity",
"346": "Origin Validation Error",
"347": "Improper Verification of Cryptographic Signature",
"348": "Use of Less Trusted Source",
"349": "Acceptance of Extraneous Untrusted Data With Trusted Data",
"350": "Reliance on Reverse DNS Resolution for a Security-Critical Action",
"351": "Insufficient Type Distinction",
"352": "Cross-Site Request Forgery (CSRF)",
"353": "Missing Support for Integrity Check",
"354": "Improper Validation of Integrity Check Value",
"355": "User Interface Security Issues",
"356": "Product UI does not Warn User of Unsafe Actions",
"357": "Insufficient UI Warning of Dangerous Operations",
"358": "Improperly Implemented Security Check for Standard",
"359": "Privacy Violation",
"360": "Trust of System Event Data",
"361": "Time and State",
"362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
"363": "Race Condition Enabling Link Following",
"364": "Signal Handler Race Condition",
"365": "Race Condition in Switch",
"366": "Race Condition within a Thread",
"367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
"368": "Context Switching Race Condition",
"369": "Divide By Zero",
"370": "Missing Check for Certificate Revocation after Initial Check",
"371": "State Issues",
"372": "Incomplete Internal State Distinction",
"373": "DEPRECATED: State Synchronization Error",
"374": "Passing Mutable Objects to an Untrusted Method",
"375": "Returning a Mutable Object to an Untrusted Caller",
"376": "Temporary File Issues",
"377": "Insecure Temporary File",
"378": "Creation of Temporary File With Insecure Permissions",
"379": "Creation of Temporary File in Directory with Incorrect Permissions",
"380": "Technology-Specific Time and State Issues",
"381": "J2EE Time and State Issues",
"382": "J2EE Bad Practices: Use of System.exit()",
"383": "J2EE Bad Practices: Direct Use of Threads",
"384": "Session Fixation",
"385": "Covert Timing Channel",
"386": "Symbolic Name not Mapping to Correct Object",
"387": "Signal Errors",
"388": "Error Handling",
"389": "Error Conditions, Return Values, Status Codes",
"390": "Detection of Error Condition Without Action",
"391": "Unchecked Error Condition",
"392": "Missing Report of Error Condition",
"393": "Return of Wrong Status Code",
"394": "Unexpected Status Code or Return Value",
"395": "Use of NullPointerException Catch to Detect NULL Pointer Dereference",
"396": "Declaration of Catch for Generic Exception",
"397": "Declaration of Throws for Generic Exception",
"398": "Indicator of Poor Code Quality",
"399": "Resource Management Errors",
"400": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
"401": "Improper Release of Memory Before Removing Last Reference ('Memory Leak')",
"402": "Transmission of Private Resources into a New Sphere ('Resource Leak')",
"403": "Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')",
"404": "Improper Resource Shutdown or Release",
"405": "Asymmetric Resource Consumption (Amplification)",
"406": "Insufficient Control of Network Message Volume (Network Amplification)",
"407": "Algorithmic Complexity",
"408": "Incorrect Behavior Order: Early Amplification",
"409": "Improper Handling of Highly Compressed Data (Data Amplification)",
"410": "Insufficient Resource Pool",
"411": "Resource Locking Problems",
"412": "Unrestricted Externally Accessible Lock",
"413": "Improper Resource Locking",
"414": "Missing Lock Check",
"415": "Double Free",
"416": "Use After Free",
"417": "Channel and Path Errors",
"418": "Channel Errors",
"419": "Unprotected Primary Channel",
"420": "Unprotected Alternate Channel",
"421": "Race Condition During Access to Alternate Channel",
"422": "Unprotected Windows Messaging Channel ('Shatter')",
"423": "DEPRECATED (Duplicate): Proxied Trusted Channel",
"424": "Improper Protection of Alternate Path",
"425": "Direct Request ('Forced Browsing')",
"426": "Untrusted Search Path",
"427": "Uncontrolled Search Path Element",
"428": "Unquoted Search Path or Element",
"429": "Handler Errors",
"430": "Deployment of Wrong Handler",
"431": "Missing Handler",
"432": "Dangerous Signal Handler not Disabled During Sensitive Operations",
"433": "Unparsed Raw Web Content Delivery",
"434": "Unrestricted Upload of File with Dangerous Type",
"435": "Interaction Error",
"436": "Interpretation Conflict",
"437": "Incomplete Model of Endpoint Features",
"438": "Behavioral Problems",
"439": "Behavioral Change in New Version or Environment",
"440": "Expected Behavior Violation",
"441": "Unintended Proxy or Intermediary ('Confused Deputy')",
"442": "Web Problems",
"443": "DEPRECATED (Duplicate): HTTP response splitting",
"444": "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')",
"445": "User Interface Errors",
"446": "UI Discrepancy for Security Feature",
"447": "Unimplemented or Unsupported Feature in UI",
"448": "Obsolete Feature in UI",
"449": "The UI Performs the Wrong Action",
"450": "Multiple Interpretations of UI Input",
"451": "UI Misrepresentation of Critical Information",
"452": "Initialization and Cleanup Errors",
"453": "Insecure Default Variable Initialization",
"454": "External Initialization of Trusted Variables or Data Stores",
"455": "Non-exit on Failed Initialization",
"456": "Missing Initialization of a Variable",
"457": "Use of Uninitialized Variable",
"458": "DEPRECATED: Incorrect Initialization",
"459": "Incomplete Cleanup",
"460": "Improper Cleanup on Thrown Exception",
"461": "Data Structure Issues",
"462": "Duplicate Key in Associative List (Alist)",
"463": "Deletion of Data Structure Sentinel",
"464": "Addition of Data Structure Sentinel",
"465": "Pointer Issues",
"466": "Return of Pointer Value Outside of Expected Range",
"467": "Use of sizeof() on a Pointer Type",
"468": "Incorrect Pointer Scaling",
"469": "Use of Pointer Subtraction to Determine Size",
"470": "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')",
"471": "Modification of Assumed-Immutable Data (MAID)",
"472": "External Control of Assumed-Immutable Web Parameter",
"473": "PHP External Variable Modification",
"474": "Use of Function with Inconsistent Implementations",
"475": "Undefined Behavior for Input to API",
"476": "NULL Pointer Dereference",
"477": "Use of Obsolete Functions",
"478": "Missing Default Case in Switch Statement",
"479": "Signal Handler Use of a Non-reentrant Function",
"480": "Use of Incorrect Operator",
"481": "Assigning instead of Comparing",
"482": "Comparing instead of Assigning",
"483": "Incorrect Block Delimitation",
"484": "Omitted Break Statement in Switch",
"485": "Insufficient Encapsulation",
"486": "Comparison of Classes by Name",
"487": "Reliance on Package-level Scope",
"488": "Exposure of Data Element to Wrong Session",
"489": "Leftover Debug Code",
"490": "Mobile Code Issues",
"491": "Public cloneable() Method Without Final ('Object Hijack')",
"492": "Use of Inner Class Containing Sensitive Data",
"493": "Critical Public Variable Without Final Modifier",
"494": "Download of Code Without Integrity Check",
"495": "Private Array-Typed Field Returned From A Public Method",
"496": "Public Data Assigned to Private Array-Typed Field",
"497": "Exposure of System Data to an Unauthorized Control Sphere",
"498": "Cloneable Class Containing Sensitive Information",
"499": "Serializable Class Containing Sensitive Data",
"500": "Public Static Field Not Marked Final",
"501": "Trust Boundary Violation",
"502": "Deserialization of Untrusted Data",
"503": "Byte/Object Code",
"504": "Motivation/Intent",
"505": "Intentionally Introduced Weakness",
"506": "Embedded Malicious Code",
"507": "Trojan Horse",
"508": "Non-Replicating Malicious Code",
"509": "Replicating Malicious Code (Virus or Worm)",
"510": "Trapdoor",
"511": "Logic/Time Bomb",
"512": "Spyware",
"513": "Intentionally Introduced Nonmalicious Weakness",
"514": "Covert Channel",
"515": "Covert Storage Channel",
"516": "DEPRECATED (Duplicate): Covert Timing Channel",
"517": "Other Intentional, Nonmalicious Weakness",
"518": "Inadvertently Introduced Weakness",
"519": ".NET Environment Issues",
"520": ".NET Misconfiguration: Use of Impersonation",
"521": "Weak Password Requirements",
"522": "Insufficiently Protected Credentials",
"523": "Unprotected Transport of Credentials",
"524": "Information Exposure Through Caching",
"525": "Information Exposure Through Browser Caching",
"526": "Information Exposure Through Environmental Variables",
"527": "Exposure of CVS Repository to an Unauthorized Control Sphere",
"528": "Exposure of Core Dump File to an Unauthorized Control Sphere",
"529": "Exposure of Access Control List Files to an Unauthorized Control Sphere",
"530": "Exposure of Backup File to an Unauthorized Control Sphere",
"531": "Information Exposure Through Test Code",
"532": "Information Exposure Through Log Files",
"533": "Information Exposure Through Server Log Files",
"534": "Information Exposure Through Debug Log Files",
"535": "Information Exposure Through Shell Error Message",
"536": "Information Exposure Through Servlet Runtime Error Message",
"537": "Information Exposure Through Java Runtime Error Message",
"538": "File and Directory Information Exposure",
"539": "Information Exposure Through Persistent Cookies",
"540": "Information Exposure Through Source Code",
"541": "Information Exposure Through Include Source Code",
"542": "Information Exposure Through Cleanup Log Files",
"543": "Use of Singleton Pattern Without Synchronization in a Multithreaded Context",
"544": "Missing Standardized Error Handling Mechanism",
"545": "Use of Dynamic Class Loading",
"546": "Suspicious Comment",
"547": "Use of Hard-coded, Security-relevant Constants",
"548": "Information Exposure Through Directory Listing",
"549": "Missing Password Field Masking",
"550": "Information Exposure Through Server Error Message",
"551": "Incorrect Behavior Order: Authorization Before Parsing and Canonicalization",
"552": "Files or Directories Accessible to External Parties",
"553": "Command Shell in Externally Accessible Directory",
"554": "ASP.NET Misconfiguration: Not Using Input Validation Framework",
"555": "J2EE Misconfiguration: Plaintext Password in Configuration File",
"556": "ASP.NET Misconfiguration: Use of Identity Impersonation",
"557": "Concurrency Issues",
"558": "Use of getlogin() in Multithreaded Application",
"559": "Often Misused: Arguments and Parameters",
"560": "Use of umask() with chmod-style Argument",
"561": "Dead Code",
"562": "Return of Stack Variable Address",
"563": "Unused Variable",
"564": "SQL Injection: Hibernate",
"565": "Reliance on Cookies without Validation and Integrity Checking",
"566": "Authorization Bypass Through User-Controlled SQL Primary Key",
"567": "Unsynchronized Access to Shared Data in a Multithreaded Context",
"568": "finalize() Method Without super.finalize()",
"569": "Expression Issues",
"570": "Expression is Always False",
"571": "Expression is Always True",
"572": "Call to Thread run() instead of start()",
"573": "Improper Following of Specification by Caller",
"574": "EJB Bad Practices: Use of Synchronization Primitives",
"575": "EJB Bad Practices: Use of AWT Swing",
"576": "EJB Bad Practices: Use of Java I/O",
"577": "EJB Bad Practices: Use of Sockets",
"578": "EJB Bad Practices: Use of Class Loader",
"579": "J2EE Bad Practices: Non-serializable Object Stored in Session",
"580": "clone() Method Without super.clone()",
"581": "Object Model Violation: Just One of Equals and Hashcode Defined",
"582": "Array Declared Public, Final, and Static",
"583": "finalize() Method Declared Public",
"584": "Return Inside Finally Block",
"585": "Empty Synchronized Block",
"586": "Explicit Call to Finalize()",
"587": "Assignment of a Fixed Address to a Pointer",
"588": "Attempt to Access Child of a Non-structure Pointer",
"589": "Call to Non-ubiquitous API",
"590": "Free of Memory not on the Heap",
"591": "Sensitive Data Storage in Improperly Locked Memory",
"592": "Authentication Bypass Issues",
"593": "Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created",
"594": "J2EE Framework: Saving Unserializable Objects to Disk",
"595": "Comparison of Object References Instead of Object Contents",
"596": "Incorrect Semantic Object Comparison",
"597": "Use of Wrong Operator in String Comparison",
"598": "Information Exposure Through Query Strings in GET Request",
"599": "Missing Validation of OpenSSL Certificate",
"600": "Uncaught Exception in Servlet ",
"601": "URL Redirection to Untrusted Site ('Open Redirect')",
"602": "Client-Side Enforcement of Server-Side Security",
"603": "Use of Client-Side Authentication",
"604": "Deprecated Entries",
"605": "Multiple Binds to the Same Port",
"606": "Unchecked Input for Loop Condition",
"607": "Public Static Final Field References Mutable Object",
"608": "Struts: Non-private Field in ActionForm Class",
"609": "Double-Checked Locking",
"610": "Externally Controlled Reference to a Resource in Another Sphere",
"611": "Improper Restriction of XML External Entity Reference ('XXE')",
"612": "Information Exposure Through Indexing of Private Data",
"613": "Insufficient Session Expiration",
"614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
"615": "Information Exposure Through Comments",
"616": "Incomplete Identification of Uploaded File Variables (PHP)",
"617": "Reachable Assertion",
"618": "Exposed Unsafe ActiveX Method",
"619": "Dangling Database Cursor ('Cursor Injection')",
"620": "Unverified Password Change",
"621": "Variable Extraction Error",
"622": "Improper Validation of Function Hook Arguments",
"623": "Unsafe ActiveX Control Marked Safe For Scripting",
"624": "Executable Regular Expression Error",
"625": "Permissive Regular Expression",
"626": "Null Byte Interaction Error (Poison Null Byte)",
"627": "Dynamic Variable Evaluation",
"628": "Function Call with Incorrectly Specified Arguments",
"629": "Weaknesses in OWASP Top Ten (2007)",
"630": "Weaknesses Examined by SAMATE",
"631": "Resource-specific Weaknesses",
"632": "Weaknesses that Affect Files or Directories",
"633": "Weaknesses that Affect Memory",
"634": "Weaknesses that Affect System Processes",
"635": "Weaknesses Used by NVD",
"636": "Not Failing Securely ('Failing Open')",
"637": "Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism')",
"638": "Not Using Complete Mediation",
"639": "Authorization Bypass Through User-Controlled Key",
"640": "Weak Password Recovery Mechanism for Forgotten Password",
"641": "Improper Restriction of Names for Files and Other Resources",
"642": "External Control of Critical State Data",
"643": "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
"644": "Improper Neutralization of HTTP Headers for Scripting Syntax",
"645": "Overly Restrictive Account Lockout Mechanism",
"646": "Reliance on File Name or Extension of Externally-Supplied File",
"647": "Use of Non-Canonical URL Paths for Authorization Decisions",
"648": "Incorrect Use of Privileged APIs",
"649": "Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking",
"650": "Trusting HTTP Permission Methods on the Server Side",
"651": "Information Exposure Through WSDL File",
"652": "Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')",
"653": "Insufficient Compartmentalization",
"654": "Reliance on a Single Factor in a Security Decision",
"655": "Insufficient Psychological Acceptability",
"656": "Reliance on Security Through Obscurity",
"657": "Violation of Secure Design Principles",
"658": "Weaknesses in Software Written in C",
"659": "Weaknesses in Software Written in C++",
"660": "Weaknesses in Software Written in Java",
"661": "Weaknesses in Software Written in PHP",
"662": "Improper Synchronization",
"663": "Use of a Non-reentrant Function in a Concurrent Context",
"664": "Improper Control of a Resource Through its Lifetime",
"665": "Improper Initialization",
"666": "Operation on Resource in Wrong Phase of Lifetime",
"667": "Improper Locking",
"668": "Exposure of Resource to Wrong Sphere",
"669": "Incorrect Resource Transfer Between Spheres",
"670": "Always-Incorrect Control Flow Implementation",
"671": "Lack of Administrator Control over Security",
"672": "Operation on a Resource after Expiration or Release",
"673": "External Influence of Sphere Definition",
"674": "Uncontrolled Recursion",
"675": "Duplicate Operations on Resource",
"676": "Use of Potentially Dangerous Function",
"677": "Weakness Base Elements",
"678": "Composites",
"679": "Chain Elements",
"680": "Integer Overflow to Buffer Overflow",
"681": "Incorrect Conversion between Numeric Types",
"682": "Incorrect Calculation",
"683": "Function Call With Incorrect Order of Arguments",
"684": "Incorrect Provision of Specified Functionality",
"685": "Function Call With Incorrect Number of Arguments",
"686": "Function Call With Incorrect Argument Type",
"687": "Function Call With Incorrectly Specified Argument Value",
"688": "Function Call With Incorrect Variable or Reference as Argument",
"689": "Permission Race Condition During Resource Copy",
"690": "Unchecked Return Value to NULL Pointer Dereference",
"691": "Insufficient Control Flow Management",
"692": "Incomplete Blacklist to Cross-Site Scripting",
"693": "Protection Mechanism Failure",
"694": "Use of Multiple Resources with Duplicate Identifier",
"695": "Use of Low-Level Functionality",
"696": "Incorrect Behavior Order",
"697": "Insufficient Comparison",
"698": "Execution After Redirect (EAR)",
"699": "Development Concepts",
"700": "Seven Pernicious Kingdoms",
"701": "Weaknesses Introduced During Design",
"702": "Weaknesses Introduced During Implementation",
"703": "Improper Check or Handling of Exceptional Conditions",
"704": "Incorrect Type Conversion or Cast",
"705": "Incorrect Control Flow Scoping",
"706": "Use of Incorrectly-Resolved Name or Reference",
"707": "Improper Enforcement of Message or Data Structure",
"708": "Incorrect Ownership Assignment",
"709": "Named Chains",
"710": "Coding Standards Violation",
"711": "Weaknesses in OWASP Top Ten (2004)",
"712": "OWASP Top Ten 2007 Category A1 - Cross Site Scripting (XSS)",
"713": "OWASP Top Ten 2007 Category A2 - Injection Flaws",
"714": "OWASP Top Ten 2007 Category A3 - Malicious File Execution",
"715": "OWASP Top Ten 2007 Category A4 - Insecure Direct Object Reference",
"716": "OWASP Top Ten 2007 Category A5 - Cross Site Request Forgery (CSRF)",
"717": "OWASP Top Ten 2007 Category A6 - Information Leakage and Improper Error Handling",
"718": "OWASP Top Ten 2007 Category A7 - Broken Authentication and Session Management",
"719": "OWASP Top Ten 2007 Category A8 - Insecure Cryptographic Storage",
"720": "OWASP Top Ten 2007 Category A9 - Insecure Communications",
"721": "OWASP Top Ten 2007 Category A10 - Failure to Restrict URL Access",
"722": "OWASP Top Ten 2004 Category A1 - Unvalidated Input",
"723": "OWASP Top Ten 2004 Category A2 - Broken Access Control",
"724": "OWASP Top Ten 2004 Category A3 - Broken Authentication and Session Management",
"725": "OWASP Top Ten 2004 Category A4 - Cross-Site Scripting (XSS) Flaws",
"726": "OWASP Top Ten 2004 Category A5 - Buffer Overflows",
"727": "OWASP Top Ten 2004 Category A6 - Injection Flaws",
"728": "OWASP Top Ten 2004 Category A7 - Improper Error Handling",
"729": "OWASP Top Ten 2004 Category A8 - Insecure Storage",
"730": "OWASP Top Ten 2004 Category A9 - Denial of Service",
"731": "OWASP Top Ten 2004 Category A10 - Insecure Configuration Management",
"732": "Incorrect Permission Assignment for Critical Resource",
"733": "Compiler Optimization Removal or Modification of Security-critical Code",
"734": "Weaknesses Addressed by the CERT C Secure Coding Standard",
"735": "CERT C Secure Coding Section 01 - Preprocessor (PRE)",
"736": "CERT C Secure Coding Section 02 - Declarations and Initialization (DCL)",
"737": "CERT C Secure Coding Section 03 - Expressions (EXP)",
"738": "CERT C Secure Coding Section 04 - Integers (INT)",
"739": "CERT C Secure Coding Section 05 - Floating Point (FLP)",
"740": "CERT C Secure Coding Section 06 - Arrays (ARR)",
"741": "CERT C Secure Coding Section 07 - Characters and Strings (STR)",
"742": "CERT C Secure Coding Section 08 - Memory Management (MEM)",
"743": "CERT C Secure Coding Section 09 - Input Output (FIO)",
"744": "CERT C Secure Coding Section 10 - Environment (ENV)",
"745": "CERT C Secure Coding Section 11 - Signals (SIG)",
"746": "CERT C Secure Coding Section 12 - Error Handling (ERR)",
"747": "CERT C Secure Coding Section 49 - Miscellaneous (MSC)",
"748": "CERT C Secure Coding Section 50 - POSIX (POS)",
"749": "Exposed Dangerous Method or Function",
"750": "Weaknesses in the 2009 CWE/SANS Top 25 Most Dangerous Programming Errors",
"751": "2009 Top 25 - Insecure Interaction Between Components",
"752": "2009 Top 25 - Risky Resource Management",
"753": "2009 Top 25 - Porous Defenses",
"754": "Improper Check for Unusual or Exceptional Conditions",
"755": "Improper Handling of Exceptional Conditions",
"756": "Missing Custom Error Page",
"757": "Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')",
"758": "Reliance on Undefined, Unspecified, or Implementation-Defined Behavior",
"759": "Use of a One-Way Hash without a Salt",
"760": "Use of a One-Way Hash with a Predictable Salt",
"761": "Free of Pointer not at Start of Buffer",
"762": "Mismatched Memory Management Routines",
"763": "Release of Invalid Pointer or Reference",
"764": "Multiple Locks of a Critical Resource",
"765": "Multiple Unlocks of a Critical Resource",
"766": "Critical Variable Declared Public",
"767": "Access to Critical Private Variable via Public Method",
"768": "Incorrect Short Circuit Evaluation",
"769": "File Descriptor Exhaustion",
"770": "Allocation of Resources Without Limits or Throttling",
"771": "Missing Reference to Active Allocated Resource",
"772": "Missing Release of Resource after Effective Lifetime",
"773": "Missing Reference to Active File Descriptor or Handle",
"774": "Allocation of File Descriptors or Handles Without Limits or Throttling",
"775": "Missing Release of File Descriptor or Handle after Effective Lifetime",
"776": "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')",
"777": "Regular Expression without Anchors",
"778": "Insufficient Logging",
"779": "Logging of Excessive Data",
"780": "Use of RSA Algorithm without OAEP",
"781": "Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code",
"782": "Exposed IOCTL with Insufficient Access Control",
"783": "Operator Precedence Logic Error",
"784": "Reliance on Cookies without Validation and Integrity Checking in a Security Decision",
"785": "Use of Path Manipulation Function without Maximum-sized Buffer",
"786": "Access of Memory Location Before Start of Buffer",
"787": "Out-of-bounds Write",
"788": "Access of Memory Location After End of Buffer",
"789": "Uncontrolled Memory Allocation",
"790": "Improper Filtering of Special Elements",
"791": "Incomplete Filtering of Special Elements",
"792": "Incomplete Filtering of One or More Instances of Special Elements",
"793": "Only Filtering One Instance of a Special Element",
"794": "Incomplete Filtering of Multiple Instances of Special Elements",
"795": "Only Filtering Special Elements at a Specified Location",
"796": "Only Filtering Special Elements Relative to a Marker",
"797": "Only Filtering Special Elements at an Absolute Position",
"798": "Use of Hard-coded Credentials",
"799": "Improper Control of Interaction Frequency",
"800": "Weaknesses in the 2010 CWE/SANS Top 25 Most Dangerous Programming Errors",
"801": "2010 Top 25 - Insecure Interaction Between Components",
"802": "2010 Top 25 - Risky Resource Management",
"803": "2010 Top 25 - Porous Defenses",
"804": "Guessable CAPTCHA",
"805": "Buffer Access with Incorrect Length Value",
"806": "Buffer Access Using Size of Source Buffer",
"807": "Reliance on Untrusted Inputs in a Security Decision",
"808": "2010 Top 25 - Weaknesses On the Cusp",
"809": "Weaknesses in OWASP Top Ten (2010)",
"810": "OWASP Top Ten 2010 Category A1 - Injection",
"811": "OWASP Top Ten 2010 Category A2 - Cross-Site Scripting (XSS)",
"812": "OWASP Top Ten 2010 Category A3 - Broken Authentication and Session Management",
"813": "OWASP Top Ten 2010 Category A4 - Insecure Direct Object References",
"814": "OWASP Top Ten 2010 Category A5 - Cross-Site Request Forgery(CSRF)",
"815": "OWASP Top Ten 2010 Category A6 - Security Misconfiguration",
"816": "OWASP Top Ten 2010 Category A7 - Insecure Cryptographic Storage",
"817": "OWASP Top Ten 2010 Category A8 - Failure to Restrict URL Access",
"818": "OWASP Top Ten 2010 Category A9 - Insufficient Transport Layer Protection",
"819": "OWASP Top Ten 2010 Category A10 - Unvalidated Redirects and Forwards",
"820": "Missing Synchronization",
"821": "Incorrect Synchronization",
"822": "Untrusted Pointer Dereference",
"823": "Use of Out-of-range Pointer Offset",
"824": "Access of Uninitialized Pointer",
"825": "Expired Pointer Dereference",
"826": "Premature Release of Resource During Expected Lifetime",
"827": "Improper Control of Document Type Definition",
"828": "Signal Handler with Functionality that is not Asynchronous-Safe",
"829": "Inclusion of Functionality from Untrusted Control Sphere",
"830": "Inclusion of Web Functionality from an Untrusted Source",
"831": "Signal Handler Function Associated with Multiple Signals",
"832": "Unlock of a Resource that is not Locked",
"833": "Deadlock",
"834": "Excessive Iteration",
"835": "Loop with Unreachable Exit Condition ('Infinite Loop')",
"836": "Use of Password Hash Instead of Password for Authentication",
"837": "Improper Enforcement of a Single, Unique Action",
"838": "Inappropriate Encoding for Output Context",
"839": "Numeric Range Comparison Without Minimum Check",
"840": "Business Logic Errors",
"841": "Improper Enforcement of Behavioral Workflow",
"842": "Placement of User into Incorrect Group",
"843": "Access of Resource Using Incompatible Type ('Type Confusion')",
"844": "Weaknesses Addressed by the CERT Java Secure Coding Standard",
"845": "CERT Java Secure Coding Section 00 - Input Validation and Data Sanitization (IDS)",
"846": "CERT Java Secure Coding Section 01 - Declarations and Initialization (DCL)",
"847": "CERT Java Secure Coding Section 02 - Expressions (EXP)",
"848": "CERT Java Secure Coding Section 03 - Numeric Types and Operations (NUM)",
"849": "CERT Java Secure Coding Section 04 - Object Orientation (OBJ)",
"850": "CERT Java Secure Coding Section 05 - Methods (MET)",
"851": "CERT Java Secure Coding Section 06 - Exceptional Behavior (ERR)",
"852": "CERT Java Secure Coding Section 07 - Visibility and Atomicity (VNA)",
"853": "CERT Java Secure Coding Section 08 - Locking (LCK)",
"854": "CERT Java Secure Coding Section 09 - Thread APIs (THI)",
"855": "CERT Java Secure Coding Section 10 - Thread Pools (TPS)",
"856": "CERT Java Secure Coding Section 11 - Thread-Safety Miscellaneous (TSM)",
"857": "CERT Java Secure Coding Section 12 - Input Output (FIO)",
"858": "CERT Java Secure Coding Section 13 - Serialization (SER)",
"859": "CERT Java Secure Coding Section 14 - Platform Security (SEC)",
"860": "CERT Java Secure Coding Section 15 - Runtime Environment (ENV)",
"861": "CERT Java Secure Coding Section 49 - Miscellaneous (MSC)",
"862": "Missing Authorization",
"863": "Incorrect Authorization",
"864": "2011 Top 25 - Insecure Interaction Between Components",
"865": "2011 Top 25 - Risky Resource Management",
"866": "2011 Top 25 - Porous Defenses",
"867": "2011 Top 25 - Weaknesses On the Cusp",
"868": "Weaknesses Addressed by the CERT C++ Secure Coding Standard",
"869": "CERT C++ Secure Coding Section 01 - Preprocessor (PRE)",
"870": "CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)",
"871": "CERT C++ Secure Coding Section 03 - Expressions (EXP)",
"872": "CERT C++ Secure Coding Section 04 - Integers (INT)",
"873": "CERT C++ Secure Coding Section 05 - Floating Point Arithmetic (FLP)",
"874": "CERT C++ Secure Coding Section 06 - Arrays and the STL (ARR)",
"875": "CERT C++ Secure Coding Section 07 - Characters and Strings (STR)",
"876": "CERT C++ Secure Coding Section 08 - Memory Management (MEM)",
"877": "CERT C++ Secure Coding Section 09 - Input Output (FIO)",
"878": "CERT C++ Secure Coding Section 10 - Environment (ENV)",
"879": "CERT C++ Secure Coding Section 11 - Signals (SIG)",
"880": "CERT C++ Secure Coding Section 12 - Exceptions and Error Handling (ERR)",
"881": "CERT C++ Secure Coding Section 13 - Object Oriented Programming (OOP)",
"882": "CERT C++ Secure Coding Section 14 - Concurrency (CON)",
"883": "CERT C++ Secure Coding Section 49 - Miscellaneous (MSC)",
"884": "CWE Cross-section",
"885": "SFP Cluster: Risky Values",
"886": "SFP Cluster: Unused entities",
"887": "SFP Cluster: API",
"888": "Software Fault Pattern (SFP) Clusters",
"889": "SFP Cluster: Exception Management",
"890": "SFP Cluster: Memory Access",
"891": "SFP Cluster: Memory Management",
"892": "SFP Cluster: Resource Management",
"893": "SFP Cluster: Path Resolution",
"894": "SFP Cluster: Synchronization",
"895": "SFP Cluster: Information Leak",
"896": "SFP Cluster: Tainted Input",
"897": "SFP Cluster: Entry Points",
"898": "SFP Cluster: Authentication",
"899": "SFP Cluster: Access Control",
"900": "Weaknesses in the 2011 CWE/SANS Top 25 Most Dangerous Software Errors",
"901": "SFP Cluster: Privilege",
"902": "SFP Cluster: Channel",
"903": "SFP Cluster: Cryptography",
"904": "SFP Cluster: Malware",
"905": "SFP Cluster: Predictability",
"906": "SFP Cluster: UI",
"907": "SFP Cluster: Other",
"908": "Use of Uninitialized Resource",
"909": "Missing Initialization of Resource",
"910": "Use of Expired File Descriptor",
"911": "Improper Update of Reference Count",
"912": "Hidden Functionality",
"913": "Improper Control of Dynamically-Managed Code Resources",
"914": "Improper Control of Dynamically-Identified Variables",
"915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
"916": "Use of Password Hash With Insufficient Computational Effort",
"917": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
"918": "Server-Side Request Forgery (SSRF)",
"919": "Weaknesses in Mobile Applications",
"920": "Improper Restriction of Power Consumption",
"921": "Storage of Sensitive Data in a Mechanism without Access Control",
"922": "Insecure Storage of Sensitive Information",
"923": "Improper Authentication of Endpoint in a Communication Channel",
"924": "Improper Enforcement of Message Integrity During Transmission in a Communication Channel",
"925": "Improper Verification of Intent by Broadcast Receiver",
"926": "Improper Restriction of Content Provider Export to Other Applications",
"927": "Use of Implicit Intent for Sensitive Communication",
"928": "Weaknesses in OWASP Top Ten (2013)",
"929": "OWASP Top Ten 2013 Category A1 - Injection",
"930": "OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management",
"931": "OWASP Top Ten 2013 Category A3 - Cross-Site Scripting (XSS)",
"932": "OWASP Top Ten 2013 Category A4 - Insecure Direct Object References",
"933": "OWASP Top Ten 2013 Category A5 - Security Misconfiguration",
"934": "OWASP Top Ten 2013 Category A6 - Sensitive Data Exposure",
"935": "OWASP Top Ten 2013 Category A7 - Missing Function Level Access Control",
"936": "OWASP Top Ten 2013 Category A8 - Cross-Site Request Forgery (CSRF)",
"937": "OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities",
"938": "OWASP Top Ten 2013 Category A10 - Unvalidated Redirects and Forwards",
"1000": "Research Concepts",
"2000": "Comprehensive CWE Dictionary"
       }


#Hard coded strings to replace new line, whitespace, tab and double squre. 
#They are used to get around format of long description. Needs better solution in the future
# Todo: Improve this. 
NEW_LINE = "bbcc5220-4a23"
NEW_WHITESPACE = "761d3ebb-09f2"
NEW_TAB = "75fb4322-03b9"
DOUBLE_SQUARE="d0781cea-e089"


data_filename = "nessus_report_JungleDiskPCI_20130623__scheduled_.nessus"

#parse argument 

desc = '''This script converts Nessus scanning result to Rackspace Nessus format for Threadfix usage. 
Example Usage:
       python nessus_convert.py nessus_report_SYDCloudBackup__scheduled_20130601.nessus  -t "Mon Aug 7 20:52:47 CDT 2013" > nessusSYD.xml
'''
parser = argparse.ArgumentParser(description=desc,  add_help=True, formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument("filename", help="The file name of Nessus scanning result to be converted")
parser.add_argument("-t", "--time", help="The scan time of this format('Mon Aug 7 20:52:47 CDT 2013')")
parser.add_argument("-o", "--output", help="The file name to save the converted result")
args = parser.parse_args()

if args.time is not None:
    scan_time = args.time

nessus_filename = args.filename
    


severity_list =["Info", "Low", "Medium", "High", "Critical"]

cwe_map = {"xyz":"CWE"}

defects = dict()

nessuss = ET.parse(nessus_filename)
hostlist = nessuss.iter('ReportHost')
count = 0
# After Report Host
for host in hostlist:
    
    host_name = host.attrib["name"]
     
    # Reportitem for each host 
    itemlist = host.iter('ReportItem')
    for s in itemlist :
        
        the_id =  s.attrib['pluginName']
        the_severity = s.attrib['severity']
        port = s.attrib['port']
        protocol = s.attrib['protocol']
        if defects.has_key(the_id):
            hosts = "%s:%s/%s" % (host_name, protocol, port)
            defects[the_id]["hosts"].add(hosts) 
            if s.find('plugin_output') is not None:
                plugin_output = s.find('plugin_output').text
            else:
                plugin_output = "None"
            details = "Plugin Output for %s:\n%s\n\n\n" % (hosts,plugin_output)
            defects[the_id]["description"] += details
            
            pass
        else:
            defects[the_id]={"hosts":set(),"severity":"", "type":"","path":"", "parameter":"", "description":""}
	    if (int(the_severity) in range(0,5)):
		    defects[the_id]["severity"] = severity_list[int(the_severity)]
	    else:
		    defects[the_id]["severity"] = "Info"
	            print "Can not find severity and use Info instead"
            if cwe_map.has_key(the_id):
                the_type = cwe_map[the_id]
            else:
                the_type = "Configuration"
            defects[the_id]["type"] = the_type        
            description = s.find('description').text
            synopsis = s.find('synopsis').text
            risk_factor = s.find('risk_factor').text
            
            see_also = ""
            if (s.find('see_also') is not None):
               see_also = s.find('see_also').text
            defects[the_id]["description"] = "Vulnerability: %s\n\n\nSystems: IMPACTED_SYSTEMS\n\n\nIP and Ports: IP_AND_PORTS\n\n\nDescription:\n%s\n\n\n\nSynopsis:\n%s\n\n\nRisk Factor:\n%s\n\n\nSee Also:\n%s\n\n\n" % (the_id,description,synopsis,risk_factor,see_also)
            hosts = "%s:%s/%s" % (host_name, protocol, port)
            defects[the_id]["hosts"].add(hosts)
            if s.find('plugin_output') is not None:
                plugin_output = s.find('plugin_output').text
            else:
                plugin_output = "None"
            details = "Plugin Output for %s:\n%s\n\n\n" % (hosts,plugin_output)
            defects[the_id]["description"] += details
            
            if s.find('cwe') is not None:
                cwe = s.find('cwe').text
            else:
                cwe = "16"
            defects[the_id]["type"] = cwes[cwe]  
        
        
            
            


def generate_sample_findings(defects):
    header = '''<?xml version="1.1"?>
<!DOCTYPE nessusIssues [
<!ELEMENT nessusIssues (issue*)>
<!ATTLIST nessusIssues NessusScanVersion CDATA "">
<!ATTLIST nessusIssues testTime CDATA "">
<!ELEMENT issue (serialNumber, type, severity, path, parameter, longDescription)>
<!ELEMENT serialNumber (#PCDATA)>
<!ELEMENT type (#PCDATA)>
<!ELEMENT severity (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT parameter (#PCDATA)>
<!ELEMENT longDescription (#PCDATA)>
]>
<nessusIssues NessusScanVersion="1.0" testTime="%s">''' % scan_time
    print header
    issue = '''
  <issue>
    <serialNumber>%s</serialNumber>
    <type>%s</type>
    <severity>%s</severity>
    <path>%s</path>
    <parameter>%s</parameter>
    <longDescription xml:space="preserve">
       <![CDATA[%s]]>
            </longDescription>
  </issue> '''
    
    count = 0
    
    for k in defects:
        defect = defects[k]
        count += 1
        hosts = defect["hosts"]
        ips = set()
        ports=set()
        for host in hosts:
            (ip,port) = host.split(":")
            ips.add(ip)
            ports.add(port)
        path = ",".join(ips)
        parameter = ",".join(ports)
        
        systems = '\n'.join(sorted(ips))
        ipports = '\n'.join(sorted(hosts))
        
            
        severity = defect["severity"]
        type = defect["type"]
        description = defect["description"]
        description = description.replace("IMPACTED_SYSTEMS", systems)
        description = description.replace("IP_AND_PORTS", ipports)
        description = description.replace("\n", NEW_LINE)
        description = description.replace(" ", NEW_WHITESPACE)
        description = description.replace("\t", NEW_TAB)
        description = description.replace("]]", DOUBLE_SQUARE)
        
        '''if len(path)>64:
            path = path[0:64]+"..."
        if len(parameter)>64:
            parameter = parameter[0:64]+"..."'''
        path = ','.join(hosts)
        if len(path)>64:
            path=path[0:64]+"..."
        parameter = str(uuid.uuid4()).replace('-','')
        print issue % (str(uuid.uuid4()).replace('-',''), type, severity, path, parameter,description)
    
    print "</nessusIssues>"
    
generate_sample_findings(defects)

def add_all_defects():
    count =0
    defect_count = 0
    filename = "mapping_v2.csv"
    mapping = get_mapping(filename)
    print mapping
    print len(mapping)
    for row in applications:
        count+=1
        print row[1]
	type = row[1].strip()
        #print get_application(1,count)
        app_id = mapping[type]
	team_id = '1'
	if app_id in ["9","10","11"]:
	    team_id = '2'
	
        defects = query_database(query2 % row[0])
        severity_list =[59,60,61,62,63]
        for defect in defects:
            (vulnType,severity,parameter,path) = get_details(defect)
            finding1 = {"apiKey": api_key, 
                        "vulnType": vulnType,
                        "severity": severity_list[int(severity)],
                        "nativeId": "nativeId",
                        "parameter": parameter,
                        "longDescription":defect,
                        "fullUrl": "http://www.rackspace.com/fullUrl",
                        "path":path}
            #print finding1
            defect_count += 1
        
            if (defect_count<=258):
                continue
            else:
                time.sleep(0.4)
                add_finding(team_id,app_id, finding1)
		print "**** Added %s, %s defect:  %s ****" % (team_id, app_id, defect_count)
    
    
 
severity_list =[59,60,61,62,63]
def test_severity(): 
    for sev in range(0,5):
        finding1 = {"apiKey": api_key, 
   "vulnType": "Information Exposure Through Browser Caching",
   "severity": severity_list[sev],
   "nativeId": "nativeId",
   "parameter": uuid.uuid4(),
   "longDescription":"test with severity of %s" % sev,
   "fullUrl": "http://www.rackspace.com/fullUrl",
   "path":uuid.uuid4()}
        #print finding1
        time.sleep(1)
        add_finding(1, finding1)
          


def test_vul(): 
    count =0
    defect_count = 0
    all_types=set()
    for row in applications:
        count+=1
        print row[1]
        defects = query_database(query2 % row[0])
        for defect in defects:
            (vulnType,severity,parameter,path) = get_details(defect)
            finding1 = {"apiKey": api_key, 
   "vulnType": vulnType,
   "severity": 5-int(severity),
   "nativeId": "nativeId",
   "parameter": parameter,
   "longDescription":defect,
   "fullUrl": "http://www.rackspace.com/fullUrl",
   "path":path}
        #print finding1
            defect_count += 1
            print (vulnType,severity,parameter,path)
            all_types.add(vulnType)
        
            if (defect_count<=0):
                continue
            else:
                #time.sleep(5)
                #add_finding(count, finding1)
                print "Added defect %s" % defect_count
  
    print all_types 
    for type in all_types:
        finding1 = {"apiKey": api_key, 
   "vulnType": type,
   "severity": 1,
   "nativeId": "nativeId",
   "parameter": "test",
   "longDescription":"test",
   "fullUrl": "http://www.rackspace.com/fullUrl",
   "path":"test"}
        time.sleep(3)
        if (not add_finding(1, finding1)):
            print type
         
    print count

#add_finding(finding1)
#add_finding(finding2)
#create_all_applications()
#add_all_defects()
#test_severity()
#create_application(1, "mytest", "http://www.rackspace.com")
#get_team(1)
