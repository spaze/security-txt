<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;

/**
 * @internal
 */
final readonly class SecurityTxtFetcherFetchHostResult
{

	public function __construct(
		private string $url,
		private string $finalUrl,
		private ?SecurityTxtFetcherResponse $response,
		private ?SecurityTxtFetcherException $exception,
	) {
	}


	public function getUrl(): string
	{
		return $this->url;
	}


	public function getFinalUrl(): string
	{
		return $this->finalUrl;
	}


	public function getContents(): ?string
	{
		return $this->response?->getContents();
	}


	public function getContentTypeHeader(): ?string
	{
		return $this->response?->getHeader('Content-Type');
	}


	public function getHttpCode(): int
	{
		return $this->exception?->getCode() ?? 200;
	}

}
