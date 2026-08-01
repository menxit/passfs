//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <Security/SecCode.h>
#include <stdlib.h>
#include <string.h>

static char *passfs_authorization_copy_string(NSString *value)
{
	if (value == nil) {
		return NULL;
	}
	const char *utf8 = [value UTF8String];
	return utf8 == NULL ? NULL : strdup(utf8);
}

static int passfs_authorization_error(
	char **error_message,
	NSString *message
) {
	if (error_message != NULL) {
		*error_message = passfs_authorization_copy_string(message);
	}
	return -1;
}

int passfs_validate_signed_process(
	int process_id,
	const char *expected_identifier,
	char **error_message
) {
	@autoreleasepool {
		pid_t pid = (pid_t)process_id;
		CFNumberRef pid_number = CFNumberCreate(
			kCFAllocatorDefault,
			kCFNumberSInt32Type,
			&pid);
		if (pid_number == NULL) {
			return passfs_authorization_error(
				error_message,
				@"Could not inspect the PassFS authorization peer");
		}
		const void *keys[] = { kSecGuestAttributePid };
		const void *values[] = { pid_number };
		CFDictionaryRef attributes = CFDictionaryCreate(
			kCFAllocatorDefault,
			keys,
			values,
			1,
			&kCFTypeDictionaryKeyCallBacks,
			&kCFTypeDictionaryValueCallBacks);
		CFRelease(pid_number);
		if (attributes == NULL) {
			return passfs_authorization_error(
				error_message,
				@"Could not inspect the PassFS authorization peer");
		}

		SecCodeRef peer_code = NULL;
		OSStatus status = SecCodeCopyGuestWithAttributes(
			NULL,
			attributes,
			kSecCSDefaultFlags,
			&peer_code);
		CFRelease(attributes);
		if (status != errSecSuccess) {
			return passfs_authorization_error(
				error_message,
				@"The PassFS authorization peer is not signed");
		}

		SecCodeRef self_code = NULL;
		CFDictionaryRef self_information = NULL;
		CFDictionaryRef peer_information = NULL;
		status = SecCodeCopySelf(kSecCSDefaultFlags, &self_code);
		if (status == errSecSuccess) {
			status = SecCodeCheckValidity(
				peer_code,
				kSecCSStrictValidate,
				NULL);
		}
		if (status == errSecSuccess) {
			status = SecCodeCopySigningInformation(
				self_code,
				kSecCSSigningInformation,
				&self_information);
		}
		if (status == errSecSuccess) {
			status = SecCodeCopySigningInformation(
				peer_code,
				kSecCSSigningInformation,
				&peer_information);
		}

		BOOL valid = NO;
		if (status == errSecSuccess &&
			self_information != NULL &&
			peer_information != NULL) {
			NSString *self_team = (NSString *)CFDictionaryGetValue(
				self_information,
				kSecCodeInfoTeamIdentifier);
			NSString *peer_team = (NSString *)CFDictionaryGetValue(
				peer_information,
				kSecCodeInfoTeamIdentifier);
			NSString *peer_identifier = (NSString *)CFDictionaryGetValue(
				peer_information,
				kSecCodeInfoIdentifier);
			NSString *expected = expected_identifier == NULL ? nil :
				[NSString stringWithUTF8String:expected_identifier];
			valid = self_team != nil &&
				peer_team != nil &&
				[self_team isEqualToString:peer_team] &&
				expected != nil &&
				[peer_identifier isEqualToString:expected];
		}

		if (self_information != NULL) {
			CFRelease(self_information);
		}
		if (peer_information != NULL) {
			CFRelease(peer_information);
		}
		if (self_code != NULL) {
			CFRelease(self_code);
		}
		CFRelease(peer_code);
		if (!valid) {
			return passfs_authorization_error(
				error_message,
				@"The PassFS authorization peer has an invalid code signature");
		}
		return 0;
	}
}
