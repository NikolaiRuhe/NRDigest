//
//  NRDigestTests.m
//  NRDigestTests
//
//  Created by Nikolai Ruhe on 09.12.13.
//  Copyright (c) 2013 Nikolai Ruhe. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "NRDigest.h"


@interface NRDigestTests : XCTestCase @end


@implementation NRDigestTests

- (void)testAllocInitThrows
{
	XCTAssertThrows([NRDigest new], @"init is expected to throw");
}

- (void)testDefaultClassExists
{
	XCTAssertNotNil([NRMutableDigest defaultDigestClass], @"default digest nil");
}

- (void)testCreateInstance
{
	XCTAssertNotNil([NRMutableDigest digest], @"can't create instance");
}

- (void)testMD5Empty
{
	XCTAssertEqualObjects([[NRMutableMD5Digest digest] description], @"d41d8cd98f00b204e9800998ecf8427e", @"empty MD5 does not match");
}

- (void)testMD5Example
{
	NRMutableDigest *digest = [NRMutableMD5Digest digest];
	[digest updateWithString:@"The quick brown fox jumps over the lazy dog" encoding:NSASCIIStringEncoding normalize:NO];
	XCTAssertEqualObjects([digest description], @"9e107d9d372bb6826bd81d3542a419d6", @"MD5 does not match");

	[digest updateWithString:@"." encoding:NSASCIIStringEncoding normalize:NO];
	XCTAssertEqualObjects([digest description], @"e4d909c290d0fb1ca068ffaddf22cbd0", @"MD5 does not match");
}

- (void)testMD5Collision
{
	static const char *text1 =
	"\xd1\x31\xdd\x02\xc5\xe6\xee\xc4\x69\x3d\x9a\x06\x98\xaf\xf9\x5c\x2f\xca\xb5\x87\x12\x46\x7e\xab\x40\x04\x58\x3e\xb8\xfb\x7f\x89"
	"\x55\xad\x34\x06\x09\xf4\xb3\x02\x83\xe4\x88\x83\x25\x71\x41\x5a\x08\x51\x25\xe8\xf7\xcd\xc9\x9f\xd9\x1d\xbd\xf2\x80\x37\x3c\x5b"
	"\xd8\x82\x3e\x31\x56\x34\x8f\x5b\xae\x6d\xac\xd4\x36\xc9\x19\xc6\xdd\x53\xe2\xb4\x87\xda\x03\xfd\x02\x39\x63\x06\xd2\x48\xcd\xa0"
	"\xe9\x9f\x33\x42\x0f\x57\x7e\xe8\xce\x54\xb6\x70\x80\xa8\x0d\x1e\xc6\x98\x21\xbc\xb6\xa8\x83\x93\x96\xf9\x65\x2b\x6f\xf7\x2a\x70";
	NRMutableDigest *digest1 = [NRMutableMD5Digest digest];
	[digest1 updateWithBytes:text1 length:strlen(text1)];

	static const char *text2 =
	"\xd1\x31\xdd\x02\xc5\xe6\xee\xc4\x69\x3d\x9a\x06\x98\xaf\xf9\x5c\x2f\xca\xb5\x07\x12\x46\x7e\xab\x40\x04\x58\x3e\xb8\xfb\x7f\x89"
	"\x55\xad\x34\x06\x09\xf4\xb3\x02\x83\xe4\x88\x83\x25\xf1\x41\x5a\x08\x51\x25\xe8\xf7\xcd\xc9\x9f\xd9\x1d\xbd\x72\x80\x37\x3c\x5b"
	"\xd8\x82\x3e\x31\x56\x34\x8f\x5b\xae\x6d\xac\xd4\x36\xc9\x19\xc6\xdd\x53\xe2\x34\x87\xda\x03\xfd\x02\x39\x63\x06\xd2\x48\xcd\xa0"
	"\xe9\x9f\x33\x42\x0f\x57\x7e\xe8\xce\x54\xb6\x70\x80\x28\x0d\x1e\xc6\x98\x21\xbc\xb6\xa8\x83\x93\x96\xf9\x65\xab\x6f\xf7\x2a\x70";
	NRMutableDigest *digest2 = [NRMutableMD5Digest digest];
	[digest2 updateWithBytes:text2 length:strlen(text2)];

	XCTAssertEqualObjects(digest1, digest2, @"expected MD5 collision does not match");
}

- (void)testMD5ContinousUpdating
{
	NRMutableDigest *digest1 = [NRMutableMD5Digest digest];
	NRMutableDigest *digest2 = [NRMutableMD5Digest digest];

	XCTAssertEqualObjects(digest1, digest2, @"digests should match");

	[digest1 updateWithString:@"foo"];

	XCTAssertNotEqualObjects(digest1, digest2, @"digests should not match");

	[digest2 updateWithString:@"foo"];

	XCTAssertEqualObjects(digest1, digest2, @"digests should match");
}

- (void)testSHA1Empty
{
	XCTAssertEqualObjects([[NRMutableSHA1Digest digest] description], @"da39a3ee5e6b4b0d3255bfef95601890afd80709", @"empty SHA1 does not match");
}

- (void)testSHA1Example
{
	NRMutableDigest *digest = [NRMutableSHA1Digest digest];
	[digest updateWithString:@"The quick brown fox jumps over the lazy dog" encoding:NSASCIIStringEncoding normalize:NO];
	XCTAssertEqualObjects([digest description], @"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", @"SHA1 does not match");

	[digest updateWithString:@"." encoding:NSASCIIStringEncoding normalize:NO];
	XCTAssertEqualObjects([digest description], @"408d94384216f890ff7a0c3528e8bed1e0b01621", @"SHA1 does not match");
}

- (void)testSHA1ContinousUpdating
{
	NRMutableDigest *digest1 = [NRMutableSHA1Digest digest];
	NRMutableDigest *digest2 = [NRMutableSHA1Digest digest];

	XCTAssertEqualObjects(digest1, digest2, @"digests should match");

	[digest1 updateWithString:@"foo"];

	XCTAssertNotEqualObjects(digest1, digest2, @"digests should not match");

	[digest2 updateWithString:@"foo"];

	XCTAssertEqualObjects(digest1, digest2, @"digests should match");
}

@end
