<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;

/**
 * @internal
 */
class SecurityTxtFetcherFetchHostResult
{

	public function __construct(
		private readonly string $url,
		private readonly string $finalUrl,
		private readonly ?string $contents,
		private readonly ?SecurityTxtFetcherException $exception,
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
		return $this->contents;
	}


	public function getHttpCode(): int
	{
		return $this->exception?->getCode() ?? 200;
	}

}
