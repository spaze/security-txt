<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use JsonSerializable;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;

/**
 * @internal
 */
class SecurityTxtFetcherFetchHostResult implements JsonSerializable
{

	public function __construct(
		private readonly string $url,
		private readonly string $finalUrl,
		private readonly ?SecurityTxtFetcherResponse $response,
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


	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		return [
			'url' => $this->getUrl(),
			'finalUrl' => $this->getFinalUrl(),
			'contents' => $this->getContents(),
			'httpCode' => $this->getHttpCode(),
		];
	}

}
