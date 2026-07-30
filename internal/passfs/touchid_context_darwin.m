//go:build darwin

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/SecBase.h>
#import <Security/SecCode.h>
#import <Security/SecRequirement.h>
#include <stdlib.h>
#include <string.h>

enum {
	PASSFS_TOUCHID_SUCCESS = 0,
	PASSFS_TOUCHID_NOT_FOUND = 1,
	PASSFS_TOUCHID_CANCELLED = 2,
	PASSFS_TOUCHID_AUTHENTICATION_FAILED = 3,
	PASSFS_TOUCHID_ERROR = 4,
	PASSFS_TOUCHID_MISSING_ENTITLEMENT = 5
};

static char *passfs_copy_utf8_string(NSString *value)
{
	if (value == nil) {
		return NULL;
	}
	const char *utf8 = [value UTF8String];
	if (utf8 == NULL) {
		return NULL;
	}
	size_t length = strlen(utf8);
	char *copy = malloc(length + 1);
	if (copy != NULL) {
		memcpy(copy, utf8, length + 1);
	}
	return copy;
}

static void passfs_set_error(char **error_message, NSError *error)
{
	if (error_message == NULL || error == nil) {
		return;
	}
	NSString *description = [NSString stringWithFormat:@"%@ (%@ %ld)",
		[error localizedDescription],
		[error domain],
		(long)[error code]];
	*error_message = passfs_copy_utf8_string(description);
}

static int passfs_result_for_error(NSError *error)
{
	if (error == nil) {
		return PASSFS_TOUCHID_ERROR;
	}
	if ([[error domain] isEqualToString:NSOSStatusErrorDomain] &&
		[error code] == errSecMissingEntitlement) {
		return PASSFS_TOUCHID_MISSING_ENTITLEMENT;
	}
	if ([[error domain] isEqualToString:LAErrorDomain]) {
		switch ([error code]) {
		case LAErrorUserCancel:
		case LAErrorAppCancel:
		case LAErrorSystemCancel:
			return PASSFS_TOUCHID_CANCELLED;
		case LAErrorAuthenticationFailed:
		case LAErrorBiometryLockout:
		case LAErrorBiometryNotAvailable:
		case LAErrorBiometryNotEnrolled:
		case LAErrorBiometryNotPaired:
		case LAErrorBiometryDisconnected:
			return PASSFS_TOUCHID_AUTHENTICATION_FAILED;
		default:
			break;
		}
	}
	return PASSFS_TOUCHID_ERROR;
}

static NSString *passfs_string(const char *value)
{
	if (value == NULL) {
		return nil;
	}
	return [[[NSString alloc]
		initWithBytes:value
		length:strlen(value)
		encoding:NSUTF8StringEncoding] autorelease];
}

static int passfs_status_error(char **error_message, OSStatus status)
{
	NSError *error = [NSError
		errorWithDomain:NSOSStatusErrorDomain
		code:status
		userInfo:nil];
	passfs_set_error(error_message, error);
	return passfs_result_for_error(error);
}

int passfs_touchid_prefers_italian(void)
{
	@autoreleasepool {
		NSArray<NSString *> *languages = [NSLocale preferredLanguages];
		if ([languages count] == 0) {
			return 0;
		}
		NSString *language = [[languages objectAtIndex:0] lowercaseString];
		return [language hasPrefix:@"it"] ? 1 : 0;
	}
}

int passfs_touchid_prepare_ui(char **error_message)
{
	@autoreleasepool {
		if (![NSThread isMainThread]) {
			if (error_message != NULL) {
				*error_message = passfs_copy_utf8_string(
					@"Touch ID helper is not running on the main thread");
			}
			return PASSFS_TOUCHID_ERROR;
		}
		NSApplication *application = [NSApplication sharedApplication];
		if (application == nil) {
			if (error_message != NULL) {
				*error_message = passfs_copy_utf8_string(
					@"Could not initialize the passfs Touch ID helper");
			}
			return PASSFS_TOUCHID_ERROR;
		}
		[application
			setActivationPolicy:NSApplicationActivationPolicyAccessory];
		[application finishLaunching];
		[application activateIgnoringOtherApps:YES];
		return PASSFS_TOUCHID_SUCCESS;
	}
}

int passfs_touchid_parent_is_trusted(
	int parent_pid,
	char **error_message
) {
	@autoreleasepool {
		pid_t pid = (pid_t)parent_pid;
		CFNumberRef pid_number = CFNumberCreate(
			kCFAllocatorDefault,
			kCFNumberSInt32Type,
			&pid);
		if (pid_number == NULL) {
			return PASSFS_TOUCHID_ERROR;
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
			return PASSFS_TOUCHID_ERROR;
		}

		SecCodeRef parent_code = NULL;
		OSStatus status = SecCodeCopyGuestWithAttributes(
			NULL,
			attributes,
			kSecCSDefaultFlags,
			&parent_code);
		CFRelease(attributes);
		if (status != errSecSuccess) {
			return passfs_status_error(error_message, status);
		}

		SecCodeRef helper_code = NULL;
		SecRequirementRef requirement = NULL;
		status = SecCodeCopySelf(
			kSecCSDefaultFlags,
			&helper_code);
		if (status == errSecSuccess) {
			status = SecCodeCopyDesignatedRequirement(
				helper_code,
				kSecCSDefaultFlags,
				&requirement);
		}
		if (status == errSecSuccess) {
			status = SecCodeCheckValidity(
				parent_code,
				kSecCSStrictValidate,
				requirement);
		}
		if (helper_code != NULL) {
			CFRelease(helper_code);
		}
		if (requirement != NULL) {
			CFRelease(requirement);
		}
		CFRelease(parent_code);
		if (status != errSecSuccess) {
			return passfs_status_error(error_message, status);
		}
		return PASSFS_TOUCHID_SUCCESS;
	}
}

int passfs_touchid_available(char **error_message)
{
	@autoreleasepool {
		LAContext *context = [[LAContext alloc] init];
		NSError *error = nil;
		BOOL available = [context
			canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
			error:&error];
		if (!available) {
			passfs_set_error(error_message, error);
		}
		[context release];
		return available ? 1 : 0;
	}
}

int passfs_touchid_store(
	const char *identifier_value,
	const unsigned char *secret_value,
	long secret_length,
	char **error_message
) {
	@autoreleasepool {
		if (@available(macOS 13.0, *)) {
			NSString *identifier = passfs_string(identifier_value);
			NSData *secret = [NSData
				dataWithBytes:secret_value
				length:(NSUInteger)secret_length];
			if (identifier == nil || secret == nil) {
				return PASSFS_TOUCHID_ERROR;
			}

			LARightStore *store = [LARightStore sharedStore];
			NSCondition *remove_condition = [[NSCondition alloc] init];
			__block BOOL remove_finished = NO;
			[store
				removeRightForIdentifier:identifier
				completion:^(NSError *error) {
					(void)error;
					[remove_condition lock];
					remove_finished = YES;
					[remove_condition signal];
					[remove_condition unlock];
				}];
			[remove_condition lock];
			while (!remove_finished) {
				[remove_condition wait];
			}
			[remove_condition unlock];
			[remove_condition release];

			LARight *right = [[LARight alloc] initWithRequirement:
				[LAAuthenticationRequirement
					biometryCurrentSetRequirement]];
			NSCondition *save_condition = [[NSCondition alloc] init];
			__block BOOL save_finished = NO;
			__block NSError *operation_error = nil;
			__block LAPersistedRight *persisted_right = nil;
			[store
				saveRight:right
				identifier:identifier
				secret:secret
				completion:^(
					LAPersistedRight *stored,
					NSError *error
				) {
					[save_condition lock];
					persisted_right = [stored retain];
					operation_error = [error retain];
					save_finished = YES;
					[save_condition signal];
					[save_condition unlock];
				}];
			[save_condition lock];
			while (!save_finished) {
				[save_condition wait];
			}
			[save_condition unlock];

			int result = PASSFS_TOUCHID_SUCCESS;
			if (operation_error != nil || persisted_right == nil) {
				passfs_set_error(error_message, operation_error);
				result = passfs_result_for_error(operation_error);
			}
			[persisted_right release];
			[operation_error release];
			[save_condition release];
			[right release];
			return result;
		}
		if (error_message != NULL) {
			*error_message = passfs_copy_utf8_string(
				@"Touch ID protection requires macOS 13 or later");
		}
		return PASSFS_TOUCHID_ERROR;
	}
}

static int passfs_fetch_right(
	NSString *identifier,
	LAPersistedRight **right,
	char **error_message
) API_AVAILABLE(macos(13.0))
{
	NSCondition *condition = [[NSCondition alloc] init];
	__block BOOL finished = NO;
	__block NSError *operation_error = nil;
	__block LAPersistedRight *persisted_right = nil;
	[[LARightStore sharedStore]
		rightForIdentifier:identifier
		completion:^(LAPersistedRight *stored, NSError *error) {
			[condition lock];
			persisted_right = [stored retain];
			operation_error = [error retain];
			finished = YES;
			[condition signal];
			[condition unlock];
		}];
	[condition lock];
	while (!finished) {
		[condition wait];
	}
	[condition unlock];

	int result = PASSFS_TOUCHID_SUCCESS;
	if (operation_error != nil) {
		passfs_set_error(error_message, operation_error);
		result = passfs_result_for_error(operation_error);
	} else if (persisted_right == nil) {
		result = PASSFS_TOUCHID_NOT_FOUND;
	}
	[operation_error release];
	[condition release];
	if (result == PASSFS_TOUCHID_SUCCESS) {
		*right = persisted_right;
	} else {
		[persisted_right release];
	}
	return result;
}

int passfs_touchid_copy(
	const char *identifier_value,
	const char *reason_value,
	unsigned char **secret_value,
	long *secret_length,
	char **error_message
) {
	@autoreleasepool {
		if (@available(macOS 13.0, *)) {
			NSString *identifier = passfs_string(identifier_value);
			NSString *reason = passfs_string(reason_value);
			if (identifier == nil || reason == nil) {
				return PASSFS_TOUCHID_ERROR;
			}
			LAPersistedRight *right = nil;
			int result = passfs_fetch_right(
				identifier,
				&right,
				error_message);
			if (result != PASSFS_TOUCHID_SUCCESS) {
				return result;
			}

			NSCondition *authorize_condition =
				[[NSCondition alloc] init];
			__block BOOL authorize_finished = NO;
			__block NSError *authorize_error = nil;
			[right
				authorizeWithLocalizedReason:reason
				completion:^(NSError *error) {
					[authorize_condition lock];
					authorize_error = [error retain];
					authorize_finished = YES;
					[authorize_condition signal];
					[authorize_condition unlock];
				}];
			[authorize_condition lock];
			while (!authorize_finished) {
				NSDate *deadline = [NSDate
					dateWithTimeIntervalSinceNow:0.05];
				[authorize_condition waitUntilDate:deadline];
				if (!authorize_finished) {
					[authorize_condition unlock];
					[[NSRunLoop currentRunLoop]
						runMode:NSDefaultRunLoopMode
						beforeDate:[NSDate
							dateWithTimeIntervalSinceNow:0.01]];
					[authorize_condition lock];
				}
			}
			[authorize_condition unlock];
			[authorize_condition release];
			if (authorize_error != nil) {
				passfs_set_error(error_message, authorize_error);
				result = passfs_result_for_error(authorize_error);
				[authorize_error release];
				[right release];
				return result;
			}

			NSCondition *secret_condition = [[NSCondition alloc] init];
			__block BOOL secret_finished = NO;
			__block NSError *secret_error = nil;
			__block NSData *secret = nil;
			[[right secret]
				loadDataWithCompletion:^(NSData *data, NSError *error) {
					[secret_condition lock];
					secret = [data retain];
					secret_error = [error retain];
					secret_finished = YES;
					[secret_condition signal];
					[secret_condition unlock];
				}];
			[secret_condition lock];
			while (!secret_finished) {
				[secret_condition wait];
			}
			[secret_condition unlock];
			[secret_condition release];

			if (secret_error != nil || secret == nil) {
				passfs_set_error(error_message, secret_error);
				result = passfs_result_for_error(secret_error);
			} else {
				NSUInteger length = [secret length];
				unsigned char *copy = malloc(length);
				if (copy == NULL && length != 0) {
					result = PASSFS_TOUCHID_ERROR;
				} else {
					if (length != 0) {
						memcpy(copy, [secret bytes], length);
					}
					*secret_value = copy;
					*secret_length = (long)length;
				}
			}

			NSCondition *deauthorize_condition =
				[[NSCondition alloc] init];
			__block BOOL deauthorize_finished = NO;
			[right deauthorizeWithCompletion:^{
				[deauthorize_condition lock];
				deauthorize_finished = YES;
				[deauthorize_condition signal];
				[deauthorize_condition unlock];
			}];
			[deauthorize_condition lock];
			while (!deauthorize_finished) {
				[deauthorize_condition wait];
			}
			[deauthorize_condition unlock];
			[deauthorize_condition release];

			[secret release];
			[secret_error release];
			[right release];
			return result;
		}
		if (error_message != NULL) {
			*error_message = passfs_copy_utf8_string(
				@"Touch ID protection requires macOS 13 or later");
		}
		return PASSFS_TOUCHID_ERROR;
	}
}

int passfs_touchid_delete(
	const char *identifier_value,
	char **error_message
) {
	@autoreleasepool {
		if (@available(macOS 13.0, *)) {
			NSString *identifier = passfs_string(identifier_value);
			if (identifier == nil) {
				return PASSFS_TOUCHID_ERROR;
			}
			NSCondition *condition = [[NSCondition alloc] init];
			__block BOOL finished = NO;
			__block NSError *operation_error = nil;
			[[LARightStore sharedStore]
				removeRightForIdentifier:identifier
				completion:^(NSError *error) {
					[condition lock];
					operation_error = [error retain];
					finished = YES;
					[condition signal];
					[condition unlock];
				}];
			[condition lock];
			while (!finished) {
				[condition wait];
			}
			[condition unlock];

			int result = PASSFS_TOUCHID_SUCCESS;
			if (operation_error != nil) {
				passfs_set_error(error_message, operation_error);
				result = passfs_result_for_error(operation_error);
			}
			[operation_error release];
			[condition release];
			return result;
		}
		if (error_message != NULL) {
			*error_message = passfs_copy_utf8_string(
				@"Touch ID protection requires macOS 13 or later");
		}
		return PASSFS_TOUCHID_ERROR;
	}
}

int passfs_touchid_exists(
	const char *identifier_value,
	char **error_message
) {
	@autoreleasepool {
		if (@available(macOS 13.0, *)) {
			NSString *identifier = passfs_string(identifier_value);
			if (identifier == nil) {
				return PASSFS_TOUCHID_ERROR;
			}
			LAPersistedRight *right = nil;
			int result = passfs_fetch_right(
				identifier,
				&right,
				error_message);
			[right release];
			return result;
		}
		if (error_message != NULL) {
			*error_message = passfs_copy_utf8_string(
				@"Touch ID protection requires macOS 13 or later");
		}
		return PASSFS_TOUCHID_ERROR;
	}
}

void passfs_free_secret(unsigned char *secret, long length)
{
	if (secret != NULL) {
		if (length > 0) {
			memset(secret, 0, (size_t)length);
		}
		free(secret);
	}
}
