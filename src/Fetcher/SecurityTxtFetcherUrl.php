<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

class SecurityTxtFetcherUrl
{

	/**
	 * @param list<string> $redirects
	 */
	public function __construct(
		private readonly string $url,
		private readonly array $redirects,
	) {
	}


	public function getUrl(): string
	{
		return $this->url;
	}


	/**
	 * @return list<string>
	 */
	public function getRedirects(): array
	{
		return $this->redirects;
	}

}
