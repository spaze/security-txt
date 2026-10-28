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


	public function testIsRegularHtmlPage(): void
	{
		$bodies = [
			"<!DOCTYPE html>\n<html lang=\"en\">",
			'<!doctype html><p>Not found</p>',
			"\u{FEFF}<!doctype html>",
			"\n\n  <html>",
			'<html lang="en">',
			'<HTML>',
			'<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN">',
			'<?xml version="1.0"?><html>',
			'<head><title>Not found</title></head>',
			'<htmlfoo>',
			"Contact: https://example.com/\n<html>",
			'# <html>',
			"<pre>\nContact: https://example.com/\n</pre>",
			'<p>Not found</p><body>',
		];
		$htmlPages = [];
		foreach ($bodies as $body) {
			foreach (['text/plain' => ['content-type' => 'text/plain; charset=utf-8'], 'text/html' => ['content-type' => 'text/html'], 'none' => []] as $type => $headers) {
				$response = new SecurityTxtFetcherResponse(200, $headers, $body, false, '1.1.1.0', SecurityTxtIpAddressType::V4);
				$htmlPages[$body][$type] = new SecurityTxtFetcherFetchHostResult(new Url('https://foo.example/'), new Url('https://foo.example/'), '192.0.2.1', SecurityTxtIpAddressType::V4, 200, $response)->isRegularHtmlPage();
			}
		}
		$all = ['text/plain' => true, 'text/html' => true, 'none' => true];
		$none = ['text/plain' => false, 'text/html' => false, 'none' => false];
		Assert::same([
			"<!DOCTYPE html>\n<html lang=\"en\">" => $all,
			'<!doctype html><p>Not found</p>' => $all,
			"\u{FEFF}<!doctype html>" => $all,
			"\n\n  <html>" => $all,
			'<html lang="en">' => $all,
			'<HTML>' => $all,
			'<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN">' => $all,
			'<?xml version="1.0"?><html>' => $none,
			'<head><title>Not found</title></head>' => $none,
			'<htmlfoo>' => $none,
			"Contact: https://example.com/\n<html>" => $none,
			'# <html>' => $none,
			"<pre>\nContact: https://example.com/\n</pre>" => $none,
			'<p>Not found</p><body>' => ['text/plain' => false, 'text/html' => true, 'none' => false],
		], $htmlPages);
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
