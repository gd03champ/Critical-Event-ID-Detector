#Author: GD

import win32evtlog
from playsound import playsound
from tkinter import messagebox
from tkinter import*
import pyttsx3

engine = pyttsx3.init()

def minimize():
        window.iconify()

def trigger():
	h=win32evtlog.OpenEventLog(None, "Security")
	flags= win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
	records=win32evtlog.ReadEventLog(h, flags, 0)
	
	print(len(records))
	for i in range(len(records)):
		print(records[i], records[i].SourceName, records[i].EventID)
		if records[i].EventID == 1100:	
			print("The event logging service has shut down")
			engine.say("The event logging service has shut down.")
			engine.runAndWait()
		elif records[i].EventID == 1101			:
			print("Audit events have been dropped by the transport.")
			engine.say("Audit events have been dropped by the transport.")
			engine.runAndWait()
		elif records[i].EventID == 1102			:
			print("The audit log was cleared")
			engine.say("The audit log was cleared.")
			engine.runAndWait()
		elif records[i].EventID == 1104			:
			print("The security Log is now full")
			engine.say("The security Log is now full.")
			engine.runAndWait()
		elif records[i].EventID == 1105			:
			print("Event log automatic backup")
			engine.say("Event log automatic backup.")
			engine.runAndWait()
		elif records[i].EventID == 1108			:
			print("The event logging service encountered an error.")
			engine.say("The event logging service encountered an error.")
			engine.runAndWait()
		elif records[i].EventID == 4618			:
			print("A monitored security event pattern has occurred.")
			engine.say("A monitored security event pattern has occurred.")
			engine.runAndWait()
		elif records[i].EventID == 4649			:
			print("A replay attack was detected. May be a harmless false positive due to misconfiguration error.")
			engine.say("A replay attack was detected. May be a harmless false positive due to misconfiguration error.")
			engine.runAndWait()
		elif records[i].EventID == 4719			:
			print("System audit policy was changed.")
			engine.say("System audit policy was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4765			:
			print("SID History was added to an account.")
			engine.say("SID History was added to an account.")
			engine.runAndWait()
		elif records[i].EventID == 4766			:
			print("An attempt to add SID History to an account failed.")
			engine.say("An attempt to add SID History to an account failed.")
			engine.runAndWait()
		elif records[i].EventID == 4794			:
			print("An attempt was made to set the Directory Services Restore Mode.")
			engine.say("An attempt was made to set the Directory Services Restore Mode.")
			engine.runAndWait()
		elif records[i].EventID == 4897			:
			print("Role separation enabled.")
			engine.say("Role separation enabled.")
			engine.runAndWait()
		elif records[i].EventID == 4964			:
			print("Special groups have been assigned to a new logon.")
			engine.say("Special groups have been assigned to a new logon.")
			engine.runAndWait()
		elif records[i].EventID == 5124			:
			print("A security setting was updated on the OCSP Responder Service.")
			engine.say("A security setting was updated on the OCSP Responder Service.")
			engine.runAndWait()
		elif records[i].EventID == 550	        :
			print("Possible denial-of-service DoS attack.")
			engine.say("Possible denial-of-service DoS attack.")
			engine.runAndWait()
		elif records[i].EventID == 4621		:
			print("Administrator recovered system from CrashOnAuditFail. Users who are not administrators will now be allowed to log on. Some auditable activity might not have been recorded.")
			engine.say("Administrator recovered system from CrashOnAuditFail. Users who are not administrators will now be allowed to log on. Some auditable activity might not have been recorded.")
			engine.runAndWait()
		elif records[i].EventID == 4675			:
			print("SIDs were filtered.")
			engine.say("SIDs were filtered.")
			engine.runAndWait()
		elif records[i].EventID == 4692			:
			print("Backup of data protection master key was attempted.")
			engine.say("Backup of data protection master key was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 4693			:
			print("Recovery of data protection master key was attempted.")
			engine.say("Recovery of data protection master key was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 4706			:
			print("A new trust was created to a domain.")
			engine.say("A new trust was created to a domain.")
			engine.runAndWait()
		elif records[i].EventID == 4713			:
			print("Kerberos policy was changed.")
			engine.say("Kerberos policy was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4714			:
			print("Encrypted data recovery policy was changed.")
			engine.say("Encrypted data recovery policy was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4715			:
			print("The audit policy (SACL) on an object was changed.")
			engine.say("The audit policy (SACL) on an object was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4716			:
			print("Trusted domain information was modified.")
			engine.say("Trusted domain information was modified.")
			engine.runAndWait()
		elif records[i].EventID == 4724			:
			print("An attempt was made to reset an account's password.")
			engine.say("An attempt was made to reset an account's password.")
			engine.runAndWait()
		elif records[i].EventID == 4727			:
			print("A security-enabled global group was created.")
			engine.say("A security-enabled global group was created.")
			engine.runAndWait()
		elif records[i].EventID == 4735			:
			print("A security-enabled local group was changed.")
			engine.say("A security-enabled local group was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4737			:
			print("A security-enabled global group was changed.")
			engine.say("A security-enabled global group was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4739			:
			print("Domain Policy was changed.")
			engine.say("Domain Policy was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4754			:
			print("A security-enabled universal group was created.")
			engine.say("A security-enabled universal group was created.")
			engine.runAndWait()
		elif records[i].EventID == 4755			:
			print("A security-enabled universal group was changed.")
			engine.say("A security-enabled universal group was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4764			:
			print("A security-disabled group was deleted")
			engine.say("A security-disabled group was deleted")
			engine.runAndWait()
		elif records[i].EventID == 4764			:
			print("A group's type was changed.")
			engine.say("A group's type was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4780			:
			print("The ACL was set on accounts which are members of administrators groups.")
			engine.say("The ACL was set on accounts which are members of administrators groups.")
			engine.runAndWait()
		elif records[i].EventID == 4816			:
			print("RPC detected an integrity violation while decrypting an incoming message.")
			engine.say("RPC detected an integrity violation while decrypting an incoming message.")
			engine.runAndWait()
		elif records[i].EventID == 4865			:
			print("A trusted forest information entry was added.")
			engine.say("A trusted forest information entry was added.")
			engine.runAndWait()
		elif records[i].EventID == 4866			:
			print("A trusted forest information entry was removed.")
			engine.say("A trusted forest information entry was removed.")
			engine.runAndWait()
		elif records[i].EventID == 4867			:
			print("A trusted forest information entry was modified.")
			engine.say("A trusted forest information entry was modified.")
			engine.runAndWait()
		elif records[i].EventID == 4868			:
			print("The certificate manager denied a pending certificate request.")
			engine.say("The certificate manager denied a pending certificate request.")
			engine.runAndWait()
		elif records[i].EventID == 4870			:
			print("Certificate Services revoked a certificate.")
			engine.say("Certificate Services revoked a certificate.")
			engine.runAndWait()
		elif records[i].EventID == 4882			:
			print("The security permissions for Certificate Services changed.")
			engine.say("The security permissions for Certificate Services changed.")
			engine.runAndWait()
		elif records[i].EventID == 4885			:
			print("The audit filter for Certificate Services changed.")
			engine.say("The audit filter for Certificate Services changed.")
			engine.runAndWait()
		elif records[i].EventID == 4890			:
			print("The certificate manager settings for Certificate Services changed.")
			engine.say("The certificate manager settings for Certificate Services changed.")
			engine.runAndWait()
		elif records[i].EventID == 4892			:
			print("A property of Certificate Services changed.")
			engine.say("A property of Certificate Services changed.")
			engine.runAndWait()
		elif records[i].EventID == 4896			:
			print("One or more rows have been deleted from the certificate database.")
			engine.say("One or more rows have been deleted from the certificate database.")
			engine.runAndWait()
		elif records[i].EventID == 4906			:
			print("The CrashOnAuditFail value has changed.")
			engine.say("The CrashOnAuditFail value has changed.")
			engine.runAndWait()
		elif records[i].EventID == 4907			:
			print("Auditing settings on object were changed.")
			engine.say("Auditing settings on object were changed.")
			engine.runAndWait()
		elif records[i].EventID == 4908			:
			print("Special Groups Logon table modified.")
			engine.say("Special Groups Logon table modified.")
			engine.runAndWait()
		elif records[i].EventID == 4912			:
			print("Per User Audit Policy was changed.")
			engine.say("Per User Audit Policy was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4960			:
			print("IPsec dropped an inbound packet that failed an integrity check. If this problem persists, it could indicate a network issue or that packets are being modified in transit to this computer. Verify that the packets sent from the remote computer are the same as those received by this computer. This error might also indicate interoperability problems with other IPsec implementations.")
			engine.say("IPsec dropped an inbound packet that failed an integrity check. If this problem persists, it could indicate a network issue or that packets are being modified in transit to this computer. Verify that the packets sent from the remote computer are the same as those received by this computer. This error might also indicate interoperability problems with other IPsec implementations.")
			engine.runAndWait()
		elif records[i].EventID == 4961			:
			print("IPsec dropped an inbound packet that failed a replay check. If this problem persists, it could indicate a replay attack against this computer.")
			engine.say("IPsec dropped an inbound packet that failed a replay check. If this problem persists, it could indicate a replay attack against this computer.")
			engine.runAndWait()
		elif records[i].EventID == 4962			:
			print("IPsec dropped an inbound packet that failed a replay check. The inbound packet had too low a sequence number to ensure it was not a replay.")
			engine.say("IPsec dropped an inbound packet that failed a replay check. The inbound packet had too low a sequence number to ensure it was not a replay.")
			engine.runAndWait()
		elif records[i].EventID == 4963			:
			print("IPsec dropped an inbound clear text packet that should have been secured. This is usually due to the remote computer changing its IPsec policy without informing this computer. This could also be a spoofing attack attempt.")
			engine.say("IPsec dropped an inbound clear text packet that should have been secured. This is usually due to the remote computer changing its IPsec policy without informing this computer. This could also be a spoofing attack attempt.")
			engine.runAndWait()
		elif records[i].EventID == 4965			:
			print("IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI). This is usually caused by malfunctioning hardware that is corrupting packets. If these errors persist, verify that the packets sent from the remote computer are the same as those received by this computer. This error may also indicate interoperability problems with other IPsec implementations. In that case, if connectivity is not impeded, then these events can be ignored.")
			engine.say("IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI). This is usually caused by malfunctioning hardware that is corrupting packets. If these errors persist, verify that the packets sent from the remote computer are the same as those received by this computer. This error may also indicate interoperability problems with other IPsec implementations. In that case, if connectivity is not impeded, then these events can be ignored.")
			engine.runAndWait()
		elif records[i].EventID == 4976			:
			print("During Main Mode negotiation, IPsec received an invalid negotiation packet. If this problem persists, it could indicate a network issue or an attempt to modify or replay this negotiation.")
			engine.say("During Main Mode negotiation, IPsec received an invalid negotiation packet. If this problem persists, it could indicate a network issue or an attempt to modify or replay this negotiation.")
			engine.runAndWait()
		elif records[i].EventID == 4977			:
			print("During Quick Mode negotiation, IPsec received an invalid negotiation packet. If this problem persists, it could indicate a network issue or an attempt to modify or replay this negotiation.")
			engine.say("During Quick Mode negotiation, IPsec received an invalid negotiation packet. If this problem persists, it could indicate a network issue or an attempt to modify or replay this negotiation.")
			engine.runAndWait()
		elif records[i].EventID == 4978			:
			print("During Extended Mode negotiation, IPsec received an invalid negotiation packet. If this problem persists, it could indicate a network issue or an attempt to modify or replay this negotiation.")
			engine.say("During Extended Mode negotiation, IPsec received an invalid negotiation packet. If this problem persists, it could indicate a network issue or an attempt to modify or replay this negotiation.")
			engine.runAndWait()
		elif records[i].EventID == 4983			:
			print("An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.")
			engine.say("An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4984			:
			print("An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.")
			engine.say("An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.")
			engine.runAndWait()
		elif records[i].EventID == 5027			:
			print("The Windows Firewall Service was unable to retrieve the security policy from the local storage. The service will continue enforcing the current policy.")
			engine.say("The Windows Firewall Service was unable to retrieve the security policy from the local storage. The service will continue enforcing the current policy.")
			engine.runAndWait()
		elif records[i].EventID == 5028			:
			print("The Windows Firewall Service was unable to parse the new security policy. The service will continue with currently enforced policy.")
			engine.say("The Windows Firewall Service was unable to parse the new security policy. The service will continue with currently enforced policy.")
			engine.runAndWait()
		elif records[i].EventID == 5029			:
			print("The Windows Firewall Service failed to initialize the driver. The service will continue to enforce the current policy.")
			engine.say("The Windows Firewall Service failed to initialize the driver. The service will continue to enforce the current policy.")
			engine.runAndWait()
		elif records[i].EventID == 5030			:
			print("The Windows Firewall Service failed to start.")
			engine.say("The Windows Firewall Service failed to start.")
			engine.runAndWait()
		elif records[i].EventID == 5035			:
			print("The Windows Firewall Driver failed to start.")
			engine.say("The Windows Firewall Driver failed to start.")
			engine.runAndWait()
		elif records[i].EventID == 5037			:
			print("The Windows Firewall Driver detected critical runtime error. Terminating.")
			engine.say("The Windows Firewall Driver detected critical runtime error. Terminating.")
			engine.runAndWait()
		elif records[i].EventID == 5038			:
			print("Code integrity determined that the image hash of a file is not valid. The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error.")
			engine.say("Code integrity determined that the image hash of a file is not valid. The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error.")
			engine.runAndWait()
		elif records[i].EventID == 5120			:
			print("OCSP Responder Service Started.")
			engine.say("OCSP Responder Service Started.")
			engine.runAndWait()
		elif records[i].EventID == 5121			:
			print("OCSP Responder Service Stopped.")
			engine.say("OCSP Responder Service Stopped.")
			engine.runAndWait()
		elif records[i].EventID == 5122			:
			print("A configuration entry changed in OCSP Responder Service.")
			engine.say("A configuration entry changed in OCSP Responder Service.")
			engine.runAndWait()
		elif records[i].EventID == 5123			:
			print("A configuration entry changed in OCSP Responder Service.")
			engine.say("A configuration entry changed in OCSP Responder Service.")
			engine.runAndWait()
		elif records[i].EventID == 5376			:
			print("Credential Manager credentials were backed up.")
			engine.say("Credential Manager credentials were backed up.")
			engine.runAndWait()
		elif records[i].EventID == 5377			:
			print("Credential Manager credentials were restored from a backup.")
			engine.say("Credential Manager credentials were restored from a backup.")
			engine.runAndWait()
		elif records[i].EventID == 5453			:
			print("An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started.")
			engine.say("An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started.")
			engine.runAndWait()
		elif records[i].EventID == 5480			:
			print("IPsec Services failed to get the complete list of network interfaces on the computer. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.")
			engine.say("IPsec Services failed to get the complete list of network interfaces on the computer. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.")
			engine.runAndWait()
		elif records[i].EventID == 5483			:
			print("IPsec Services failed to initialize RPC server. IPsec Services could not be started.")
			engine.say("IPsec Services failed to initialize RPC server. IPsec Services could not be started.")
			engine.runAndWait()
		elif records[i].EventID == 5484			:
			print("IPsec Services has experienced a critical failure and has been shut down. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.")
			engine.say("IPsec Services has experienced a critical failure and has been shut down. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.")
			engine.runAndWait()
		elif records[i].EventID == 5485			:
			print("IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.")
			engine.say("IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.")
			engine.runAndWait()
		elif records[i].EventID == 6145			:
			print("One or more errors occurred while processing security policy in the Group Policy objects.")
			engine.say("One or more errors occurred while processing security policy in the Group Policy objects.")
			engine.runAndWait()
		elif records[i].EventID == 6273			:
			print("Network Policy Server denied access to a user.")
			engine.say("Network Policy Server denied access to a user.")
			engine.runAndWait()
		elif records[i].EventID == 6274		:
			print("Network Policy Server discarded the request for a user.")
			engine.say("Network Policy Server discarded the request for a user.")
			engine.runAndWait()
		elif records[i].EventID == 6275			:
			print("Network Policy Server discarded the accounting request for a user.")
			engine.say("Network Policy Server discarded the accounting request for a user.")
			engine.runAndWait()
		elif records[i].EventID == 6276			:
			print("Network Policy Server quarantined a user.")
			engine.say("Network Policy Server quarantined a user.")
			engine.runAndWait()
		elif records[i].EventID == 6277			:
			print("Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy.")
			engine.say("Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy.")
			engine.runAndWait()
		elif records[i].EventID == 6278			:
			print("Network Policy Server granted full access to a user because the host met the defined health policy.")
			engine.say("Network Policy Server granted full access to a user because the host met the defined health policy.")
			engine.runAndWait()
		elif records[i].EventID == 6279			:
			print("Network Policy Server locked the user account due to repeated failed authentication attempts.")
			engine.say("Network Policy Server locked the user account due to repeated failed authentication attempts.")
			engine.runAndWait()
		elif records[i].EventID == 6280			:
			print("Network Policy Server unlocked the user account.")
			engine.say("Network Policy Server unlocked the user account.")
			engine.runAndWait()
		elif records[i].EventID == 640	        	:
			print("General account database changed.")
			engine.say("General account database changed.")
			engine.runAndWait()
		elif records[i].EventID == 619	        	:
			print("Quality of Service Policy changed.")
			engine.say("Quality of Service Policy changed.")
			engine.runAndWait()
		elif records[i].EventID == 24586			:
			print("An error was encountered converting volume.")
			engine.say("An error was encountered converting volume.")
			engine.runAndWait()
		elif records[i].EventID == 24592			:
			print("An attempt to automatically restart conversion on volume %2 failed.")
			engine.say("An attempt to automatically restart conversion on volume percent 2 failed.")
			engine.runAndWait()
		elif records[i].EventID == 24593			:
			print("Metadata write: Volume %2 returning errors while trying to modify metadata. If failures continue, decrypt volume.")
			engine.say("Metadata write: Volume percent 2 returning errors while trying to modify metadata. If failures continue, decrypt volume.")
			engine.runAndWait()
		elif records[i].EventID == 24594			:
			print("Metadata rebuild: An attempt to write a copy of metadata on volume %2 failed and may appear as disk corruption. If failures continue, decrypt volume.")
			engine.say("Metadata rebuild: An attempt to write a copy of metadata on volume percent 2 failed and may appear as disk corruption. If failures continue, decrypt volume.")
			engine.runAndWait()
		elif records[i].EventID == 4608			:
			print("Windows is starting up.")
			engine.say("Windows is starting up.")
			engine.runAndWait()
		elif records[i].EventID == 4609			:
			print("Windows is shutting down.")
			engine.say("Windows is shutting down.")
			engine.runAndWait()
		elif records[i].EventID == 4610			:
			print("An authentication package has been loaded by the Local Security Authority.")
			engine.say("An authentication package has been loaded by the Local Security Authority.")
			engine.runAndWait()
		elif records[i].EventID == 4611			:
			print("A trusted logon process has been registered with the Local Security Authority.")
			engine.say("A trusted logon process has been registered with the Local Security Authority.")
			engine.runAndWait()
		elif records[i].EventID == 4612			:
			print("Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.")
			engine.say("Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.")
			engine.runAndWait()
		elif records[i].EventID == 4614			:
			print("A notification package has been loaded by the Security Account Manager.")
			engine.say("A notification package has been loaded by the Security Account Manager.")
			engine.runAndWait()
		elif records[i].EventID == 4615			:
			print("Invalid use of LPC port.")
			engine.say("Invalid use of LPC port.")
			engine.runAndWait()
		elif records[i].EventID == 4616			:
			print("The system time was changed.")
			engine.say("The system time was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4622			:
			print("A security package has been loaded by the Local Security Authority.")
			engine.say("A security package has been loaded by the Local Security Authority.")
			engine.runAndWait()
		elif records[i].EventID == 4624			:
			print("An account was successfully logged on.")
			engine.say("An account was successfully logged on.")
			engine.runAndWait()
		elif records[i].EventID == 4625			:
			print("An account failed to log on.")
			engine.say("An account failed to log on.")
			engine.runAndWait()
		elif records[i].EventID == 4634			:
			print("An account was logged off.")
			engine.say("An account was logged off.")
			engine.runAndWait()
		elif records[i].EventID == 4646			:
			print("IKE DoS-prevention mode started.")
			engine.say("IKE DoS-prevention mode started.")
			engine.runAndWait()
		elif records[i].EventID == 4647			:
			print("User initiated logoff.")
			engine.say("User initiated logoff.")
			engine.runAndWait()
		elif records[i].EventID == 4648			:
			print("A logon was attempted using explicit credentials.")
			engine.say("A logon was attempted using explicit credentials.")
			engine.runAndWait()
		elif records[i].EventID == 4650			:
			print("An IPsec Main Mode security association was established. Extended Mode was not enabled. Certificate authentication was not used.")
			engine.say("An IPsec Main Mode security association was established. Extended Mode was not enabled. Certificate authentication was not used.")
			engine.runAndWait()
		elif records[i].EventID == 4651			:
			print("An IPsec Main Mode security association was established. Extended Mode was not enabled. A certificate was used for authentication.")
			engine.say("An IPsec Main Mode security association was established. Extended Mode was not enabled. A certificate was used for authentication.")
			engine.runAndWait()
		elif records[i].EventID == 4652			:
			print("An IPsec Main Mode negotiation failed.")
			engine.say("An IPsec Main Mode negotiation failed.")
			engine.runAndWait()
		elif records[i].EventID == 4653			:
			print("An IPsec Main Mode negotiation failed.")
			engine.say("An IPsec Quick Mode negotiation failed.")
			engine.runAndWait()
		elif records[i].EventID == 4654			:
			print("An IPsec Quick Mode negotiation failed.")
			engine.say("An IPsec Quick Mode negotiation failed.")
			engine.runAndWait()
		elif records[i].EventID == 4655			:
			print("An IPsec Main Mode security association ended.")
			engine.say("An IPsec Main Mode security association ended.")
			engine.runAndWait()
		elif records[i].EventID == 4656			:
			print("A handle to an object was requested.")
			engine.say("A handle to an object was requested.")
			engine.runAndWait()
		elif records[i].EventID == 4657			:
			print("A registry value was modified.")
			engine.say("A registry value was modified.")
			engine.runAndWait()
		elif records[i].EventID == 4658			:
			print("The handle to an object was closed.")
			engine.say("The handle to an object was closed.")
			engine.runAndWait()
		elif records[i].EventID == 4659			:
			print("A handle to an object was requested with intent to delete.")
			engine.say("A handle to an object was requested with intent to delete.")
			engine.runAndWait()
		elif records[i].EventID == 4660			:
			print("An object was deleted.")
			engine.say("An object was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4661			:
			print("A handle to an object was requested.")
			engine.say("A handle to an object was requested.")
			engine.runAndWait()
		elif records[i].EventID == 4662			:
			print("An operation was performed on an object.")
			engine.say("An operation was performed on an object.")
			engine.runAndWait()
		elif records[i].EventID == 4663			:
			print("An attempt was made to access an object.")
			engine.say("An attempt was made to access an object.")
			engine.runAndWait()
		elif records[i].EventID == 4664			:
			print("An attempt was made to create a hard link.")
			engine.say("An attempt was made to create a hard link.")
			engine.runAndWait()
		elif records[i].EventID == 4665			:
			print("An attempt was made to create an application client context.")
			engine.say("An attempt was made to create an application client context.")
			engine.runAndWait()
		elif records[i].EventID == 4666			:
			print("An application attempted an operation.")
			engine.say("An application attempted an operation.")
			engine.runAndWait()
		elif records[i].EventID == 4667			:
			print("An application client context was deleted.")
			engine.say("An application client context was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4668			:
			print("An application was initialized.")
			engine.say("An application was initialized.")
			engine.runAndWait()
		elif records[i].EventID == 4670			:
			print("Permissions on an object were changed.")
			engine.say("Permissions on an object were changed.")
			engine.runAndWait()
		elif records[i].EventID == 4671			:
			print("An application attempted to access a blocked ordinal through the TBS.")
			engine.say("An application attempted to access a blocked ordinal through the TBS.")
			engine.runAndWait()
		elif records[i].EventID == 4672			:
			print("Special privileges assigned to new logon.")
			engine.say("Special privileges assigned to new logon.")
			engine.runAndWait()
		elif records[i].EventID == 4673			:
			print("A privileged service was called.")
			engine.say("A privileged service was called.")
			engine.runAndWait()
		elif records[i].EventID == 4674			:
			print("An operation was attempted on a privileged object.")
			engine.say("An operation was attempted on a privileged object.")
			engine.runAndWait()
		elif records[i].EventID == 4688			:
			print("A new process has been created.")
			engine.say("A new process has been created.")
			engine.runAndWait()
		elif records[i].EventID == 4689			:
			print("A process has exited.")
			engine.say("A process has exited.")
			engine.runAndWait()
		elif records[i].EventID == 4690			:
			print("An attempt was made to duplicate a handle to an object.")
			engine.say("An attempt was made to duplicate a handle to an object.")
			engine.runAndWait()
		elif records[i].EventID == 4691			:
			print("Indirect access to an object was requested.")
			engine.say("Indirect access to an object was requested.")
			engine.runAndWait()
		elif records[i].EventID == 4694			:
			print("Protection of auditable protected data was attempted.")
			engine.say("Protection of auditable protected data was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 4695			:
			print("Unprotection of auditable protected data was attempted.")
			engine.say("Unprotection of auditable protected data was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 4696			:
			print("A primary token was assigned to process.")
			engine.say("A primary token was assigned to process.")
			engine.runAndWait()
		elif records[i].EventID == 4697			:
			print("Attempt to install a service.")
			engine.say("Attempt to install a service.")
			engine.runAndWait()
		elif records[i].EventID == 4698			:
			print("A scheduled task was created.")
			engine.say("A scheduled task was created.")
			engine.runAndWait()
		elif records[i].EventID == 4699			:
			print("A scheduled task was deleted.")
			engine.say("A scheduled task was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4700			:
			print("A scheduled task was enabled.")
			engine.say("A scheduled task was enabled.")
			engine.runAndWait()
		elif records[i].EventID == 4701			:
			print("A scheduled task was disabled.")
			engine.say("A scheduled task was disabled.")
			engine.runAndWait()
		elif records[i].EventID == 4702			:
			print("A scheduled task was updated.")
			engine.say("A scheduled task was updated.")
			engine.runAndWait()
		elif records[i].EventID == 4704			:
			print("A user right was assigned.")
			engine.say("A user right was assigned.")
			engine.runAndWait()
		elif records[i].EventID == 4705			:
			print("A user right was removed.")
			engine.say("A user right was removed.")
			engine.runAndWait()
		elif records[i].EventID == 4707			:
			print("A trust to a domain was removed.")
			engine.say("A trust to a domain was removed.")
			engine.runAndWait()
		elif records[i].EventID == 4709			:
			print("IPsec Services was started.")
			engine.say("IPsec Services was started.")
			engine.runAndWait()
		elif records[i].EventID == 4710			:
			print("IPsec Services was disabled.")
			engine.say("IPsec Services was disabled.")
			engine.runAndWait()
		elif records[i].EventID == 4711		:
			print("May contain any one of the following: PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer. PAStore Engine applied Active Directory storage IPsec policy on the computer. PAStore Engine applied local registry storage IPsec policy on the computer. PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer. PAStore Engine failed to apply Active Directory storage IPsec policy on the computer. PAStore Engine failed to apply local registry storage IPsec policy on the computer. PAStore Engine failed to apply some rules of the active IPsec policy on the computer. PAStore Engine failed to load directory storage IPsec policy on the computer. PAStore Engine loaded directory storage IPsec policy on the computer. PAStore Engine failed to load local storage IPsec policy on the computer. PAStore Engine loaded local storage IPsec policy on the computer.PAStore Engine polled for changes to the active IPsec policy and deleted no changes.")
			engine.say("")
			engine.runAndWait()
		elif records[i].EventID == 4712			:
			print("IPsec Services encountered a potentially serious failure.")
			engine.say("IPsec Services encountered a potentially serious failure.")
			engine.runAndWait()
		elif records[i].EventID == 4717			:
			print("System security access was granted to an account.")
			engine.say("System security access was granted to an account.")
			engine.runAndWait()
		elif records[i].EventID == 4718			:
			print("System security access was removed from an account.")
			engine.say("System security access was removed from an account.")
			engine.runAndWait()
		elif records[i].EventID == 4720		:
			print("A user account was created.")
			engine.say("A user account was created.")
			engine.runAndWait()
		elif records[i].EventID == 4722			:
			print("A user account was enabled.")
			engine.say("A user account was enabled.")
			engine.runAndWait()
		elif records[i].EventID == 4723		:
			print("An attempt was made to change an account's password.")
			engine.say("An attempt was made to change an account's password.")
			engine.runAndWait()
		elif records[i].EventID == 4725			:
			print("A user account was disabled.")
			engine.say("A user account was disabled.")
			engine.runAndWait()
		elif records[i].EventID == 4726			:
			print("A user account was deleted.")
			engine.say("A user account was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4728			:
			print("A member was added to a security-enabled global group.")
			engine.say("A member was added to a security-enabled global group.")
			engine.runAndWait()
		elif records[i].EventID == 4729			:
			print("A member was removed from a security-enabled global group.")
			engine.say("A member was removed from a security-enabled global group.")
			engine.runAndWait()
		elif records[i].EventID == 4730			:
			print("A security-enabled global group was deleted.")
			engine.say("A security-enabled global group was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4731			:
			print("A security-enabled local group was created.")
			engine.say("A security-enabled local group was created.")
			engine.runAndWait()
		elif records[i].EventID == 4732			:
			print("A member was added to a security-enabled local group.")
			engine.say("A member was added to a security-enabled local group.")
			engine.runAndWait()
		elif records[i].EventID == 4733			:
			print("A member was removed from a security-enabled local group.")
			engine.say("A member was removed from a security-enabled local group.")
			engine.runAndWait()
		elif records[i].EventID == 4734			:
			print("A security-enabled local group was deleted.")
			engine.say("A security-enabled local group was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4738			:
			print("A user account was changed.")
			engine.say("A user account was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4740			:
			print("A user account was locked out.")
			engine.say("A user account was locked out.")
			engine.runAndWait()
		elif records[i].EventID == 4741			:
			print("A computer account was changed.")
			engine.say("A computer account was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4742			:
			print("A computer account was changed.")
			engine.say("A computer account was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4743			:
			print("A computer account was deleted.")
			engine.say("A computer account was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4744			:
			print("A security-disabled local group was created.")
			engine.say("A security-disabled local group was created.")
			engine.runAndWait()
		elif records[i].EventID == 4745			:
			print("A security-disabled local group was changed.")
			engine.say("A security-disabled local group was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4746			:
			print("A member was added to a security-disabled local group.")
			engine.say("A member was added to a security-disabled local group.")
			engine.runAndWait()
		elif records[i].EventID == 4747			:
			print("A member was removed from a security-disabled local group.")
			engine.say("A member was removed from a security-disabled local group.")
			engine.runAndWait()
		elif records[i].EventID == 4748			:
			print("A security-disabled local group was deleted.")
			engine.say("A security-disabled local group was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4749		:
			print("A security-disabled global group was created.")
			engine.say("A security-disabled global group was created.")
			engine.runAndWait()
		elif records[i].EventID == 4750			:
			print("A security-disabled global group was changed.")
			engine.say("A security-disabled global group was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4751			:
			print("A member was added to a security-disabled global group.")
			engine.say("A member was added to a security-disabled global group.")
			engine.runAndWait()
		elif records[i].EventID == 4752			:
			print("A member was removed from a security-disabled global group.")
			engine.say("A member was removed from a security-disabled global group.")
			engine.runAndWait()
		elif records[i].EventID == 4753			:
			print("A security-disabled global group was deleted.")
			engine.say("A security-disabled global group was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4756			:
			print("A member was added to a security-enabled universal group.")
			engine.say("A member was added to a security-enabled universal group.")
			engine.runAndWait()
		elif records[i].EventID == 4757			:
			print("A member was removed from a security-enabled universal group.")
			engine.say("A member was removed from a security-enabled universal group.")
			engine.runAndWait()
		elif records[i].EventID == 4758			:
			print("A security-enabled universal group was deleted.")
			engine.say("A security-enabled universal group was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4759		:
			print("A security-disabled universal group was created.")
			engine.say("A security-disabled universal group was created.")
			engine.runAndWait()
		elif records[i].EventID == 4760			:
			print("A security-disabled universal group was changed.")
			engine.say("A security-disabled universal group was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4761			:
			print("A member was added to a security-disabled universal group.")
			engine.say("A member was added to a security-disabled universal group.")
			engine.runAndWait()
		elif records[i].EventID == 4762			:
			print("A member was removed from a security-disabled universal group.")
			engine.say("A member was removed from a security-disabled universal group.")
			engine.runAndWait()
		elif records[i].EventID == 4767			:
			print("A user account was unlocked.")
			engine.say("A user account was unlocked.")
			engine.runAndWait()
		elif records[i].EventID == 4768			:
			print("A Kerberos authentication ticket TGT was requested.")
			engine.say("A Kerberos authentication ticket TGT was requested.")
			engine.runAndWait()
		elif records[i].EventID == 4769			:
			print("A Kerberos service ticket was requested.")
			engine.say("A Kerberos service ticket was requested.")
			engine.runAndWait()
		elif records[i].EventID == 4770			:
			print("A Kerberos service ticket was renewed.")
			engine.say("A Kerberos service ticket was renewed.")
			engine.runAndWait()
		elif records[i].EventID == 4771			:
			print("Kerberos pre-authentication failed.")
			engine.say("Kerberos pre-authentication failed.")
			engine.runAndWait()
		elif records[i].EventID == 4772			:
			print("A Kerberos authentication ticket request failed.")
			engine.say("A Kerberos authentication ticket request failed.")
			engine.runAndWait()
		elif records[i].EventID == 4774			:
			print("An account was mapped for logon.")
			engine.say("An account was mapped for logon.")
			engine.runAndWait()
		elif records[i].EventID == 4775			:
			print("An account could not be mapped for logon.")
			engine.say("An account could not be mapped for logon.")
			engine.runAndWait()
		elif records[i].EventID == 4776			:
			print("The domain controller attempted to validate the credentials for an account.")
			engine.say("The domain controller attempted to validate the credentials for an account.")
			engine.runAndWait()
		elif records[i].EventID == 4777			:
			print("The domain controller failed to validate the credentials for an account.")
			engine.say("The domain controller failed to validate the credentials for an account.")
			engine.runAndWait()
		elif records[i].EventID == 4778			:
			print("A session was reconnected to a Window Station.")
			engine.say("A session was reconnected to a Window Station.")
			engine.runAndWait()
		elif records[i].EventID == 4779			:
			print("A session was disconnected from a Window Station.")
			engine.say("A session was disconnected from a Window Station.")
			engine.runAndWait()
		elif records[i].EventID == 4781			:
			print("The name of an account was changed:")
			engine.say("The name of an account was changed:")
			engine.runAndWait()
		elif records[i].EventID == 4782			:
			print("The password hash an account was accessed.")
			engine.say("The password hash an account was accessed.")
			engine.runAndWait()
		elif records[i].EventID == 4783			:
			print("A basic application group was created.")
			engine.say("A basic application group was created.")
			engine.runAndWait()
		elif records[i].EventID == 4784			:
			print("A basic application group was changed.")
			engine.say("A basic application group was changed.")
			engine.runAndWait()
		elif records[i].EventID == 4785			:
			print("A member was added to a basic application group.")
			engine.say("A member was added to a basic application group.")
			engine.runAndWait()
		elif records[i].EventID == 4786			:
			print("A member was removed from a basic application group.")
			engine.say("A member was removed from a basic application group.")
			engine.runAndWait()
		elif records[i].EventID == 4787			:
			print("A nonmember was added to a basic application group.")
			engine.say("A nonmember was added to a basic application group.")
			engine.runAndWait()
		elif records[i].EventID == 4788			:
			print("A nonmember was removed from a basic application group.")
			engine.say("A nonmember was removed from a basic application group.")
			engine.runAndWait()
		elif records[i].EventID == 4789			:
			print("A basic application group was deleted.")
			engine.say("A basic application group was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4790			:
			print("An LDAP query group was created.")
			engine.say("An LDAP query group was created.")
			engine.runAndWait()
		elif records[i].EventID == 4793			:
			print("The Password Policy Checking API was called.")
			engine.say("The Password Policy Checking API was called.")
			engine.runAndWait()
		elif records[i].EventID == 4800			:
			print("The workstation was locked.")
			engine.say("The workstation was locked.")
			engine.runAndWait()
		elif records[i].EventID == 4801			:
			print("The workstation was unlocked.")
			engine.say("The workstation was unlocked.")
			engine.runAndWait()
		elif records[i].EventID == 4802			:
			print("The screen saver was invoked.")
			engine.say("The screen saver was invoked.")
			engine.runAndWait()
		elif records[i].EventID == 4803			:
			print("The screen saver was dismissed.")
			engine.say("The screen saver was dismissed.")
			engine.runAndWait()
		elif records[i].EventID == 4864			:
			print("A namespace collision was detected.")
			engine.say("A namespace collision was detected.")
			engine.runAndWait()
		elif records[i].EventID == 4869			:
			print("Certificate Services received a resubmitted certificate request.")
			engine.say("Certificate Services received a resubmitted certificate request.")
			engine.runAndWait()
		elif records[i].EventID == 4871			:
			print("Certificate Services received a request to publish the certificate revocation list CRL.")
			engine.say("Certificate Services received a request to publish the certificate revocation list CRL.")
			engine.runAndWait()
		elif records[i].EventID == 4872			:
			print("Certificate Services published the certificate revocation list CRL.")
			engine.say("Certificate Services published the certificate revocation list CRL.")
			engine.runAndWait()
		elif records[i].EventID == 4873			:
			print("A certificate request extension changed.")
			engine.say("A certificate request extension changed.")
			engine.runAndWait()
		elif records[i].EventID == 4874			:
			print("One or more certificate request attributes changed.")
			engine.say("One or more certificate request attributes changed.")
			engine.runAndWait()
		elif records[i].EventID == 4875			:
			print("Certificate Services received a request to shut down.")
			engine.say("Certificate Services received a request to shut down.")
			engine.runAndWait()
		elif records[i].EventID == 4876			:
			print("Certificate Services backup started.")
			engine.say("Certificate Services backup started.")
			engine.runAndWait()
		elif records[i].EventID == 4877			:
			print("Certificate Services backup completed.")
			engine.say("Certificate Services backup completed.")
			engine.runAndWait()
		elif records[i].EventID == 4878			:
			print("Certificate Services restore started.")
			engine.say("Certificate Services restore started.")
			engine.runAndWait()
		elif records[i].EventID == 4879			:
			print("Certificate Services restore completed.")
			engine.say("Certificate Services restore completed.")
			engine.runAndWait()
		elif records[i].EventID == 4880			:
			print("Certificate Services started.")
			engine.say("Certificate Services started.")
			engine.runAndWait()
		elif records[i].EventID == 4881			:
			print("Certificate Services stopped.")
			engine.say("Certificate Services stopped.")
			engine.runAndWait()
		elif records[i].EventID == 4883			:
			print("Certificate Services retrieved an archived key.")
			engine.say("Certificate Services retrieved an archived key.")
			engine.runAndWait()
		elif records[i].EventID == 4884			:
			print("Certificate Services imported a certificate into its database.")
			engine.say("Certificate Services imported a certificate into its database.")
			engine.runAndWait()
		elif records[i].EventID == 4886			:
			print("Certificate Services received a certificate request.")
			engine.say("Certificate Services received a certificate request.")
			engine.runAndWait()
		elif records[i].EventID == 4887			:
			print("Certificate Services approved a certificate request and issued a certificate.")
			engine.say("Certificate Services approved a certificate request and issued a certificate.")
			engine.runAndWait()
		elif records[i].EventID == 4888			:
			print("Certificate Services denied a certificate request.")
			engine.say("Certificate Services denied a certificate request.")
			engine.runAndWait()
		elif records[i].EventID == 4889			:
			print("Certificate Services set the status of a certificate request to pending.")
			engine.say("Certificate Services set the status of a certificate request to pending.")
			engine.runAndWait()
		elif records[i].EventID == 4891			:
			print("A configuration entry changed in Certificate Services.")
			engine.say("A configuration entry changed in Certificate Services.")
			engine.runAndWait()
		elif records[i].EventID == 4893			:
			print("Certificate Services archived a key.")
			engine.say("Certificate Services archived a key.")
			engine.runAndWait()
		elif records[i].EventID == 4894			:
			print("Certificate Services imported and archived a key.")
			engine.say("Certificate Services imported and archived a key.")
			engine.runAndWait()
		elif records[i].EventID == 4895			:
			print("Certificate Services published the CA certificate to Active Directory Domain Services.")
			engine.say("Certificate Services published the CA certificate to Active Directory Domain Services.")
			engine.runAndWait()
		elif records[i].EventID == 4902			:
			print("The Per-user audit policy table was created.")
			engine.say("The Per-user audit policy table was created.")
			engine.runAndWait()
		elif records[i].EventID == 4904			:
			print("An attempt was made to register a security event source.")
			engine.say("An attempt was made to register a security event source.")
			engine.runAndWait()
		elif records[i].EventID == 4905			:
			print("An attempt was made to unregister a security event source.")
			engine.say("An attempt was made to unregister a security event source.")
			engine.runAndWait()
		elif records[i].EventID == 4909			:
			print("The local policy settings for the TBS were changed.")
			engine.say("The local policy settings for the TBS were changed.")
			engine.runAndWait()
		elif records[i].EventID == 4910			:
			print("The Group Policy settings for the TBS were changed.")
			engine.say("The Group Policy settings for the TBS were changed.")
			engine.runAndWait()
		elif records[i].EventID == 4928			:
			print("An Active Directory replica source naming context was established.")
			engine.say("An Active Directory replica source naming context was established.")
			engine.runAndWait()
		elif records[i].EventID == 4929			:
			print("An Active Directory replica source naming context was removed.")
			engine.say("An Active Directory replica source naming context was removed.")
			engine.runAndWait()
		elif records[i].EventID == 4930			:
			print("An Active Directory replica source naming context was modified.")
			engine.say("An Active Directory replica source naming context was modified.")
			engine.runAndWait()
		elif records[i].EventID == 4931			:
			print("An Active Directory replica destination naming context was modified.")
			engine.say("An Active Directory replica destination naming context was modified.")
			engine.runAndWait()
		elif records[i].EventID == 4932			:
			print("Synchronization of a replica of an Active Directory naming context has begun.")
			engine.say("Synchronization of a replica of an Active Directory naming context has begun.")
			engine.runAndWait()
		elif records[i].EventID == 4933			:
			print("Synchronization of a replica of an Active Directory naming context has ended.")
			engine.say("Synchronization of a replica of an Active Directory naming context has ended.")
			engine.runAndWait()
		elif records[i].EventID == 4934			:
			print("Attributes of an Active Directory object were replicated.")
			engine.say("Attributes of an Active Directory object were replicated.")
			engine.runAndWait()
		elif records[i].EventID == 4935			:
			print("Replication failure begins.")
			engine.say("Replication failure begins.")
			engine.runAndWait()
		elif records[i].EventID == 4936			:
			print("Replication failure ends.")
			engine.say("Replication failure ends.")
			engine.runAndWait()
		elif records[i].EventID == 4937			:
			print("A lingering object was removed from a replica.")
			engine.say("A lingering object was removed from a replica.")
			engine.runAndWait()
		elif records[i].EventID == 4944			:
			print("The following policy was active when the Windows Firewall started.")
			engine.say("The following policy was active when the Windows Firewall started.")
			engine.runAndWait()
		elif records[i].EventID == 4945			:
			print("A rule was listed when the Windows Firewall started.")
			engine.say("A rule was listed when the Windows Firewall started.")
			engine.runAndWait()
		elif records[i].EventID == 4946			:
			print("A change has been made to Windows Firewall exception list. A rule was added.")
			engine.say("A change has been made to Windows Firewall exception list. A rule was added.")
			engine.runAndWait()
		elif records[i].EventID == 4947			:
			print("A change has been made to Windows Firewall exception list. A rule was modified.")
			engine.say("A change has been made to Windows Firewall exception list. A rule was modified.")
			engine.runAndWait()
		elif records[i].EventID == 4948			:
			print("A change has been made to Windows Firewall exception list. A rule was deleted.")
			engine.say("A change has been made to Windows Firewall exception list. A rule was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 4949			:
			print("Windows Firewall settings were restored to the default values.")
			engine.say("Windows Firewall settings were restored to the default values.")
			engine.runAndWait()
		elif records[i].EventID == 4950			:
			print("A Windows Firewall setting has changed.")
			engine.say("A Windows Firewall setting has changed.")
			engine.runAndWait()
		elif records[i].EventID == 4951			:
			print("A rule has been ignored because its major version number was not recognized by Windows Firewall.")
			engine.say("A rule has been ignored because its major version number was not recognized by Windows Firewall.")
			engine.runAndWait()
		elif records[i].EventID == 4952			:
			print("Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall. The other parts of the rule will be enforced.")
			engine.say("Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall. The other parts of the rule will be enforced.")
			engine.runAndWait()
		elif records[i].EventID == 4953			:
			print("A rule has been ignored by Windows Firewall because it could not parse the rule.")
			engine.say("A rule has been ignored by Windows Firewall because it could not parse the rule.")
			engine.runAndWait()
		elif records[i].EventID == 4954			:
			print("Windows Firewall Group Policy settings have changed. The new settings have been applied.")
			engine.say("Windows Firewall Group Policy settings have changed. The new settings have been applied.")
			engine.runAndWait()
		elif records[i].EventID == 4956			:
			print("Windows Firewall has changed the active profile.")
			engine.say("Windows Firewall has changed the active profile.")
			engine.runAndWait()
		elif records[i].EventID == 4957			:
			print("Windows Firewall did not apply the following rule:")
			engine.say("Windows Firewall did not apply the following rule:")
			engine.runAndWait()
		elif records[i].EventID == 4958			:
			print("Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer.")
			engine.say("Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer.")
			engine.runAndWait()
		elif records[i].EventID == 4979			:
			print("IPsec Main Mode and Extended Mode security associations were established.")
			engine.say("IPsec Main Mode and Extended Mode security associations were established.")
			engine.runAndWait()
		elif records[i].EventID == 4980			:
			print("IPsec Main Mode and Extended Mode security associations were established.")
			engine.say("IPsec Main Mode and Extended Mode security associations were established.")
			engine.runAndWait()
		elif records[i].EventID == 4981			:
			print("IPsec Main Mode and Extended Mode security associations were established.")
			engine.say("IPsec Main Mode and Extended Mode security associations were established.")
			engine.runAndWait()
		elif records[i].EventID == 4982		:
			print("IPsec Main Mode and Extended Mode security associations were established.")
			engine.say("IPsec Main Mode and Extended Mode security associations were established.")
			engine.runAndWait()
		elif records[i].EventID == 4985			:
			print("The state of a transaction has changed.")
			engine.say("The state of a transaction has changed.")
			engine.runAndWait()
		elif records[i].EventID == 5024			:
			print("The Windows Firewall Service has started successfully.")
			engine.say("The Windows Firewall Service has started successfully.")
			engine.runAndWait()
		elif records[i].EventID == 5025			:
			print("The Windows Firewall Service has been stopped.")
			engine.say("The Windows Firewall Service has been stopped.")
			engine.runAndWait()
		elif records[i].EventID == 5030			:
			print("The Windows Firewall Service failed to start.")
			engine.say("The Windows Firewall Service failed to start.")
			engine.runAndWait()
		elif records[i].EventID == 5031			:
			print("The Windows Firewall Service blocked an application from accepting incoming connections on the network.")
			engine.say("The Windows Firewall Service blocked an application from accepting incoming connections on the network.")
			engine.runAndWait()
		elif records[i].EventID == 5032			:
			print("Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network.")
			engine.say("Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network.")
			engine.runAndWait()
		elif records[i].EventID == 5033			:
			print("The Windows Firewall Driver has started successfully.")
			engine.say("The Windows Firewall Driver has started successfully.")
			engine.runAndWait()
		elif records[i].EventID == 5034			:
			print("The Windows Firewall Driver has been stopped.")
			engine.say("The Windows Firewall Driver has been stopped.")
			engine.runAndWait()
		elif records[i].EventID == 5035			:
			print("The Windows Firewall Driver failed to start.")
			engine.say("The Windows Firewall Driver failed to start.")
			engine.runAndWait()
		elif records[i].EventID == 5039			:
			print("A registry key was virtualized.")
			engine.say("A registry key was virtualized.")
			engine.runAndWait()
		elif records[i].EventID == 5040			:
			print("A change has been made to IPsec settings. An Authentication Set was added.")
			engine.say("A change has been made to IPsec settings. An Authentication Set was added.")
			engine.runAndWait()
		elif records[i].EventID == 5041			:
			print("A change has been made to IPsec settings. An Authentication Set was modified.")
			engine.say("A change has been made to IPsec settings. An Authentication Set was modified.")
			engine.runAndWait()
		elif records[i].EventID == 5042			:
			print("A change has been made to IPsec settings. An Authentication Set was deleted.")
			engine.say("A change has been made to IPsec settings. An Authentication Set was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 5043		:
			print("A change has been made to IPsec settings. A Connection Security Rule was added.")
			engine.say("A change has been made to IPsec settings. A Connection Security Rule was added.")
			engine.runAndWait()
		elif records[i].EventID == 5044			:
			print("A change has been made to IPsec settings. A Connection Security Rule was modified.")
			engine.say("A change has been made to IPsec settings. A Connection Security Rule was modified.")
			engine.runAndWait()
		elif records[i].EventID == 5045			:
			print("A change has been made to IPsec settings. A Connection Security Rule was deleted.")
			engine.say("A change has been made to IPsec settings. A Connection Security Rule was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 5046			:
			print("A change has been made to IPsec settings. A Crypto Set was added.")
			engine.say("A change has been made to IPsec settings. A Crypto Set was added.")
			engine.runAndWait()
		elif records[i].EventID == 5047		:
			print("A change has been made to IPsec settings. A Crypto Set was modified.")
			engine.say("A change has been made to IPsec settings. A Crypto Set was modified.")
			engine.runAndWait()
		elif records[i].EventID == 5048			:
			print("A change has been made to IPsec settings. A Crypto Set was deleted.")
			engine.say("A change has been made to IPsec settings. A Crypto Set was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 5049			:
			print("An IPsec Security Association was deleted")
			engine.say("An IPsec Security Association was deleted")
			engine.runAndWait()
		elif records[i].EventID == 5050			:
			print("An attempt to programmatically disable the Windows Firewall using a call to InetFwProfile.FirewallEnabled(False)")
			engine.say("An attempt to programmatically disable the Windows Firewall using a call to InetFwProfile.FirewallEnabled(False)")
			engine.runAndWait()
		elif records[i].EventID == 5051			:
			print("A file was virtualized.")
			engine.say("A file was virtualized.")
			engine.runAndWait()
		elif records[i].EventID == 5056			:
			print("A cryptographic self test was performed.")
			engine.say("A cryptographic self test was performed.")
			engine.runAndWait()
		elif records[i].EventID == 5057			:
			print("A cryptographic primitive operation failed.")
			engine.say("A cryptographic primitive operation failed.")
			engine.runAndWait()
		elif records[i].EventID == 5058		:
			print("Key file operation.")
			engine.say("Key file operation.")
			engine.runAndWait()
		elif records[i].EventID == 5059			:
			print("Key migration operation.")
			engine.say("Key migration operation.")
			engine.runAndWait()
		elif records[i].EventID == 5060			:
			print("Verification operation failed.")
			engine.say("Verification operation failed.")
			engine.runAndWait()
		elif records[i].EventID == 5061			:
			print("Cryptographic operation.")
			engine.say("Cryptographic operation.")
			engine.runAndWait()
		elif records[i].EventID == 5062		:
			print("A kernel-mode cryptographic self test was performed.")
			engine.say("A kernel-mode cryptographic self test was performed.")
			engine.runAndWait()
		elif records[i].EventID == 5063			:
			print("A cryptographic provider operation was attempted.")
			engine.say("A cryptographic provider operation was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 5064			:
			print("A cryptographic context operation was attempted.")
			engine.say("A cryptographic context operation was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 5065			:
			print("A cryptographic context modification was attempted.")
			engine.say("A cryptographic context modification was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 5066		:
			print("A cryptographic function operation was attempted.")
			engine.say("A cryptographic function operation was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 5067			:
			print("A cryptographic function modification was attempted.")
			engine.say("A cryptographic function modification was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 5068			:
			print("A cryptographic function provider operation was attempted.")
			engine.say("A cryptographic function provider operation was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 5069			:
			print("A cryptographic function property operation was attempted.")
			engine.say("A cryptographic function property operation was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 5070			:
			print("A cryptographic function property modification was attempted.")
			engine.say("A cryptographic function property modification was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 5125			:
			print("A request was submitted to the OCSP Responder Service.")
			engine.say("A request was submitted to the OCSP Responder Service.")
			engine.runAndWait()
		elif records[i].EventID == 5126			:
			print("Signing Certificate was automatically updated by the OCSP Responder Service.")
			engine.say("Signing Certificate was automatically updated by the OCSP Responder Service.")
			engine.runAndWait()
		elif records[i].EventID == 5127			:
			print("The OCSP Revocation Provider successfully updated the revocation information.")
			engine.say("The OCSP Revocation Provider successfully updated the revocation information.")
			engine.runAndWait()
		elif records[i].EventID == 5136		:
			print("A directory service object was modified.")
			engine.say("A directory service object was modified.")
			engine.runAndWait()
		elif records[i].EventID == 5137			:
			print("A directory service object was created.")
			engine.say("A directory service object was created.")
			engine.runAndWait()
		elif records[i].EventID == 5138		:
			print("A directory service object was undeleted.")
			engine.say("A directory service object was undeleted.")
			engine.runAndWait()
		elif records[i].EventID == 5139			:
			print("A directory service object was moved.")
			engine.say("A directory service object was moved.")
			engine.runAndWait()
		elif records[i].EventID == 5140			:
			print("A network share object was accessed.")
			engine.say("A network share object was accessed.")
			engine.runAndWait()
		elif records[i].EventID == 5141		:
			print("A directory service object was deleted.")
			engine.say("A directory service object was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 5152			:
			print("The Windows Filtering Platform blocked a packet.")
			engine.say("The Windows Filtering Platform blocked a packet.")
			engine.runAndWait()
		elif records[i].EventID == 5153			:
			print("A more restrictive Windows Filtering Platform filter has blocked a packet.")
			engine.say("A more restrictive Windows Filtering Platform filter has blocked a packet.")
			engine.runAndWait()
		elif records[i].EventID == 5154			:
			print("The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections.")
			engine.say("The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections.")
			engine.runAndWait()
		elif records[i].EventID == 5155		:
			print("The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections.")
			engine.say("The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections.")
			engine.runAndWait()
		elif records[i].EventID == 5156		:
			print("The Windows Filtering Platform has allowed a connection.")
			engine.say("The Windows Filtering Platform has allowed a connection.")
			engine.runAndWait()
		elif records[i].EventID == 5157			:
			print("The Windows Filtering Platform has blocked a connection.")
			engine.say("The Windows Filtering Platform has blocked a connection.")
			engine.runAndWait()
		elif records[i].EventID == 5158		:
			print("The Windows Filtering Platform has permitted a bind to a local port.")
			engine.say("The Windows Filtering Platform has permitted a bind to a local port.")
			engine.runAndWait()
		elif records[i].EventID == 5159			:
			print("The Windows Filtering Platform has blocked a bind to a local port.")
			engine.say("The Windows Filtering Platform has blocked a bind to a local port.")
			engine.runAndWait()
		elif records[i].EventID == 5378			:
			print("The requested credentials delegation was disallowed by policy.")
			engine.say("The requested credentials delegation was disallowed by policy.")
			engine.runAndWait()
		elif records[i].EventID == 5440			:
			print("The following callout was present when the Windows Filtering Platform Base Filtering Engine started.")
			engine.say("The following callout was present when the Windows Filtering Platform Base Filtering Engine started.")
			engine.runAndWait()
		elif records[i].EventID == 5441			:
			print("The following filter was present when the Windows Filtering Platform Base Filtering Engine started.")
			engine.say("The following filter was present when the Windows Filtering Platform Base Filtering Engine started.")
			engine.runAndWait()
		elif records[i].EventID == 5442			:
			print("The following provider was present when the Windows Filtering Platform Base Filtering Engine started.")
			engine.say("The following provider was present when the Windows Filtering Platform Base Filtering Engine started.")
			engine.runAndWait()
		elif records[i].EventID == 5443			:
			print("The following provider context was present when the Windows Filtering Platform Base Filtering Engine started.")
			engine.say("The following provider context was present when the Windows Filtering Platform Base Filtering Engine started.")
			engine.runAndWait()
		elif records[i].EventID == 5444			:
			print("The following sublayer was present when the Windows Filtering Platform Base Filtering Engine started.")
			engine.say("The following sublayer was present when the Windows Filtering Platform Base Filtering Engine started.")
			engine.runAndWait()
		elif records[i].EventID == 5446			:
			print("A Windows Filtering Platform callout has been changed.")
			engine.say("A Windows Filtering Platform callout has been changed.")
			engine.runAndWait()
		elif records[i].EventID == 5447		:
			print("A Windows Filtering Platform filter has been changed.")
			engine.say("A Windows Filtering Platform filter has been changed.")
			engine.runAndWait()
		elif records[i].EventID == 5448			:
			print("A Windows Filtering Platform provider has been changed.")
			engine.say("A Windows Filtering Platform provider has been changed.")
			engine.runAndWait()
		elif records[i].EventID == 5449			:
			print("A Windows Filtering Platform provider context has been changed.")
			engine.say("A Windows Filtering Platform provider context has been changed.")
			engine.runAndWait()
		elif records[i].EventID == 5450			:
			print("A Windows Filtering Platform sublayer has been changed.")
			engine.say("A Windows Filtering Platform sublayer has been changed.")
			engine.runAndWait()
		elif records[i].EventID == 5451			:
			print("An IPsec Quick Mode security association was established.")
			engine.say("An IPsec Quick Mode security association was established.")
			engine.runAndWait()
		elif records[i].EventID == 5452			:
			print("An IPsec Quick Mode security association ended.")
			engine.say("An IPsec Quick Mode security association ended.")
			engine.runAndWait()
		elif records[i].EventID == 5456			:
			print("PAStore Engine applied Active Directory storage IPsec policy on the computer.")
			engine.say("PAStore Engine applied Active Directory storage IPsec policy on the computer.")
			engine.runAndWait()
		elif records[i].EventID == 5457			:
			print("PAStore Engine failed to apply Active Directory storage IPsec policy on the computer.")
			engine.say("PAStore Engine failed to apply Active Directory storage IPsec policy on the computer.")
			engine.runAndWait()
		elif records[i].EventID == 5458			:
			print("PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer.")
			engine.say("PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer.")
			engine.runAndWait()
		elif records[i].EventID == 5459			:
			print("PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer.")
			engine.say("PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer.")
			engine.runAndWait()
		elif records[i].EventID == 5460		:
			print("PAStore Engine applied local registry storage IPsec policy on the computer.")
			engine.say("PAStore Engine applied local registry storage IPsec policy on the computer.")
			engine.runAndWait()
		elif records[i].EventID == 5461			:
			print("PAStore Engine failed to apply local registry storage IPsec policy on the computer.")
			engine.say("PAStore Engine failed to apply local registry storage IPsec policy on the computer.")
			engine.runAndWait()
		elif records[i].EventID == 5462			:
			print("PAStore Engine failed to apply some rules of the active IPsec policy on the computer. Use the IP Security Monitor snap-in to diagnose the problem.")
			engine.say("PAStore Engine failed to apply some rules of the active IPsec policy on the computer. Use the IP Security Monitor snap-in to diagnose the problem.")
			engine.runAndWait()
		elif records[i].EventID == 5463			:
			print("PAStore Engine polled for changes to the active IPsec policy and detected no changes.")
			engine.say("PAStore Engine polled for changes to the active IPsec policy and detected no changes.")
			engine.runAndWait()
		elif records[i].EventID == 5464			:
			print("PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them to IPsec Services.")
			engine.say("PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them to IPsec Services.")
			engine.runAndWait()
		elif records[i].EventID == 5465		:
			print("PAStore Engine received a control for forced reloading of IPsec policy and processed the control successfully.")
			engine.say("PAStore Engine received a control for forced reloading of IPsec policy and processed the control successfully.")
			engine.runAndWait()
		elif records[i].EventID == 5466	:
			print("PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead. Any changes made to the Active Directory IPsec policy since the last poll could not be applied.")
			engine.say("PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead. Any changes made to the Active Directory IPsec policy since the last poll could not be applied.")
			engine.runAndWait()
		elif records[i].EventID == 5468			:
			print("PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, found changes to the policy, and applied those changes. The cached copy of the Active Directory IPsec policy is no longer being used.")
			engine.say("PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, found changes to the policy, and applied those changes. The cached copy of the Active Directory IPsec policy is no longer being used.")
			engine.runAndWait()
		elif records[i].EventID == 5471		:
			print("PAStore Engine loaded local storage IPsec policy on the computer.")
			engine.say("PAStore Engine loaded local storage IPsec policy on the computer.")
			engine.runAndWait()
		elif records[i].EventID == 5472		:
			print("PAStore Engine failed to load local storage IPsec policy on the computer.")
			engine.say("PAStore Engine failed to load local storage IPsec policy on the computer.")
			engine.runAndWait()
		elif records[i].EventID == 5473		:
			print("PAStore Engine loaded directory storage IPsec policy on the computer.")
			engine.say("PAStore Engine loaded directory storage IPsec policy on the computer.")
			engine.runAndWait()
		elif records[i].EventID == 5474			:
			print("PAStore Engine failed to load directory storage IPsec policy on the computer.")
			engine.say("PAStore Engine failed to load directory storage IPsec policy on the computer.")
			engine.runAndWait()
		elif records[i].EventID == 5479			:
			print("IPsec Services has been shut down successfully. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.")
			engine.say("IPsec Services has been shut down successfully. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.")
			engine.runAndWait()
		elif records[i].EventID == 5632			:
			print("A request was made to authenticate to a wireless network.")
			engine.say("A request was made to authenticate to a wireless network.")
			engine.runAndWait()
		elif records[i].EventID == 5633		:
			print("A request was made to authenticate to a wired network.")
			engine.say("A request was made to authenticate to a wired network.")
			engine.runAndWait()
		elif records[i].EventID == 5712			:
			print("A Remote Procedure Call (RPC) was attempted.")
			engine.say("A Remote Procedure Call (RPC) was attempted.")
			engine.runAndWait()
		elif records[i].EventID == 5888			:
			print("An object in the COM+ Catalog was modified.")
			engine.say("An object in the COM+ Catalog was modified.")
			engine.runAndWait()
		elif records[i].EventID == 5889			:
			print("An object was deleted from the COM+ Catalog.")
			engine.say("An object was deleted from the COM+ Catalog.")
			engine.runAndWait()
		elif records[i].EventID == 5890			:
			print("An object was added to the COM+ Catalog.")
			engine.say("An object was added to the COM+ Catalog.")
			engine.runAndWait()
		elif records[i].EventID == 6008			:
			print("The previous system shutdown was unexpected.")
			engine.say("The previous system shutdown was unexpected.")
			engine.runAndWait()
		elif records[i].EventID == 6144			:
			print("Security policy in the Group Policy objects has been applied successfully.")
			engine.say("Security policy in the Group Policy objects has been applied successfully.")
			engine.runAndWait()
		elif records[i].EventID == 6272			:
			print("Network Policy Server granted access to a user.")
			engine.say("Network Policy Server granted access to a user.")
			engine.runAndWait()
		elif records[i].EventID == 24577			:
			print("Encryption of volume started.")
			engine.say("Encryption of volume started.")
			engine.runAndWait()
		elif records[i].EventID == 24578			:
			print("Encryption of volume stopped.")
			engine.say("Encryption of volume stopped.")
			engine.runAndWait()
		elif records[i].EventID == 24579			:
			print("Encryption of volume completed.")
			engine.say("Encryption of volume completed.")
			engine.runAndWait()
		elif records[i].EventID == 24580			:
			print("Decryption of volume started.")
			engine.say("Decryption of volume started.")
			engine.runAndWait()
		elif records[i].EventID == 24581			:
			print("Decryption of volume stopped.")
			engine.say("Decryption of volume stopped.")
			engine.runAndWait()
		elif records[i].EventID == 24582			:
			print("Decryption of volume completed.")
			engine.say("Decryption of volume completed.")
			engine.runAndWait()
		elif records[i].EventID == 24583			:
			print("Conversion worker thread for volume started.")
			engine.say("Conversion worker thread for volume started.")
			engine.runAndWait()
		elif records[i].EventID == 24584			:
			print("Conversion worker thread for volume temporarily stopped.")
			engine.say("Conversion worker thread for volume temporarily stopped.")
			engine.runAndWait()
		elif records[i].EventID == 24588			:
			print("The conversion operation on volume %2 encountered a bad sector error. Please validate the data on this volume.")
			engine.say("The conversion operation on volume percent 2 encountered a bad sector error. Please validate the data on this volume.")
			engine.runAndWait()
		elif records[i].EventID == 24595			:
			print("Volume %2 contains bad clusters. These clusters will be skipped during conversion.")
			engine.say("Volume percent 2 contains bad clusters. These clusters will be skipped during conversion.")
			engine.runAndWait()
		elif records[i].EventID == 5049			:
			print("An IPsec Security Association was deleted.")
			engine.say("An IPsec Security Association was deleted.")
			engine.runAndWait()
		elif records[i].EventID == 5478			:
			print("IPsec Services has started successfully.")
			engine.say("IPsec Services has started successfully.")
			engine.runAndWait()
		else					:
			print("No suspicious activity detected.")
			engine.say("No suspicious activity detected.")
			engine.runAndWait()

	print(exit)
	exit()

window=Tk()
btn=Button(window, text="START", fg='blue', command=lambda:[minimize(), trigger()])
btn.pack()
btn.place(x=200, y=180)
lab1=Label(window, text="Welcome to Critical Event ID Detector.", fg='red', font=("Helvetica", 16))
lab2=Label(window, text="Press Start to initiate the program.", fg='red', font=("Helvetica", 16))
lab1.place(x=60, y=50)
lab2.place(x=90, y=80)
window.title('Critical Event ID Viewer')
window.geometry("500x400+20+20")
window.mainloop()
	
'''
engine.say("")
engine.runAndWait()
'''