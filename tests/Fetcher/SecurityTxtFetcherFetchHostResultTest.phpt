<?php
/**
 * @testCase
 * @noinspection PhpDocMissingThrowsInspection
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/../bootstrap.php';

final class SecurityTxtFetcherFetchHostResultTest extends TestCase
{

	public function testGetContentTypeHeader(): void
	{
		$response = new SecurityTxtFetcherResponse(200, ['content-type' => 'tExt/HtMl; charset=Win-1337'], 'contents', true, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$wellKnown = new SecurityTxtFetcherFetchHostResult(new Url('https://foo.example/'), new Url('https://foo2.example/'), '192.0.2.1', SecurityTxtIpAddressType::V4, 200, $response);
		$contentType = $wellKnown->getContentType();
		assert($contentType !== null);
		Assert::same('text/html', $contentType->getLowercaseContentType());
		Assert::same('charset=win-1337', $contentType->getLowercaseCharsetParameter());
	}


	public function testGetCharsetParameter(): void
	{
		$headers = [
			'text/plain; charset=utf-8',
			'text/plain;charset=UTF-8',
			'Text/Plain; Charset="UTF-8"',
			'text/plain; charset="utf\-8"',
			'text/plain; format=flowed; charset=utf-8',
			'text/plain; charset=utf-8; format=flowed',
			'text/plain; charset="utf-8"; format=flowed',
			'text/plain; charset="utf-8" ; format=flowed',
			'text/plain;; charset=utf-8',
			'text/plain; format; charset=utf-8',
			'text/plain; foo="a;charset=win-1337"; charset=utf-8',
			'text/plain; foo="a\\";charset=win-1337"; charset=utf-8',
			'text/plain; foo = "a;charset=win-1337"; charset=utf-8',
			'text/plain; charset=utf-8; charset=win-1337',
			'text/plain; charset = win-1337; charset=utf-8',
			'text/plain; charset=win-1337',
			'text/plain; charset = utf-8',
			'text/plain; Charset = UTF-8 ; format=flowed',
			'text/plain; charset:utf-8',
			'text/plain; charset',
			'text/plain; charset=utf-8 win-1337',
			'text/plain; charset="utf-8',
			'text/plain; charsets=utf-8',
			'text/plain; charsets:utf-8',
			'text/plain; foo charset=utf-8',
			'text/plain; foo="a;charset=utf-8;"',
			'text/plain; foo="a; charset=utf-8',
			'text/plain; format=flowed',
			'text/plain;',
			'text/plain',
		];
		$parameters = [];
		foreach ($headers as $header) {
			$response = new SecurityTxtFetcherResponse(200, ['content-type' => $header], 'contents', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
			$contentType = new SecurityTxtFetcherFetchHostResult(new Url('https://foo.example/'), new Url('https://foo.example/'), '192.0.2.1', SecurityTxtIpAddressType::V4, 200, $response)->getContentType();
			assert($contentType !== null);
			$parameters[$header] = [$contentType->getCharsetParameter(), $contentType->getLowercaseCharsetParameter()];
		}
		Assert::same([
			'text/plain; charset=utf-8' => ['charset=utf-8', 'charset=utf-8'],
			'text/plain;charset=UTF-8' => ['charset=UTF-8', 'charset=utf-8'],
			'Text/Plain; Charset="UTF-8"' => ['Charset="UTF-8"', 'charset=utf-8'],
			'text/plain; charset="utf\-8"' => ['charset="utf\-8"', 'charset=utf-8'],
			'text/plain; format=flowed; charset=utf-8' => ['charset=utf-8', 'charset=utf-8'],
			'text/plain; charset=utf-8; format=flowed' => ['charset=utf-8', 'charset=utf-8'],
			'text/plain; charset="utf-8"; format=flowed' => ['charset="utf-8"', 'charset=utf-8'],
			'text/plain; charset="utf-8" ; format=flowed' => ['charset="utf-8"', 'charset=utf-8'],
			'text/plain;; charset=utf-8' => ['charset=utf-8', 'charset=utf-8'],
			'text/plain; format; charset=utf-8' => ['charset=utf-8', 'charset=utf-8'],
			'text/plain; foo="a;charset=win-1337"; charset=utf-8' => ['charset=utf-8', 'charset=utf-8'],
			'text/plain; foo="a\\";charset=win-1337"; charset=utf-8' => ['charset=utf-8', 'charset=utf-8'],
			'text/plain; foo = "a;charset=win-1337"; charset=utf-8' => ['charset=utf-8', 'charset=utf-8'],
			'text/plain; charset=utf-8; charset=win-1337' => ['charset=utf-8', 'charset=utf-8'],
			'text/plain; charset = win-1337; charset=utf-8' => ['charset = win-1337', 'charset = win-1337'],
			'text/plain; charset=win-1337' => ['charset=win-1337', 'charset=win-1337'],
			'text/plain; charset = utf-8' => ['charset = utf-8', 'charset = utf-8'],
			'text/plain; Charset = UTF-8 ; format=flowed' => ['Charset = UTF-8', 'charset = utf-8'],
			'text/plain; charset:utf-8' => ['charset:utf-8', 'charset:utf-8'],
			'text/plain; charset' => ['charset', 'charset'],
			'text/plain; charset=utf-8 win-1337' => ['charset=utf-8 win-1337', 'charset=utf-8 win-1337'],
			'text/plain; charset="utf-8' => ['charset="utf-8', 'charset="utf-8'],
			'text/plain; charsets=utf-8' => [null, null],
			'text/plain; charsets:utf-8' => [null, null],
			'text/plain; foo charset=utf-8' => [null, null],
			'text/plain; foo="a;charset=utf-8;"' => [null, null],
			'text/plain; foo="a; charset=utf-8' => [null, null],
			'text/plain; format=flowed' => [null, null],
			'text/plain;' => [null, null],
			'text/plain' => [null, null],
		], $parameters);
	}

}

(new SecurityTxtFetcherFetchHostResultTest())->run();
