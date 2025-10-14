<?php

namespace ChernegaSergiy\XAuthConnect\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class XAuthConnectUser implements ResourceOwnerInterface
{
    protected array $response;

    public function __construct(array $response)
    {
        $this->response = $response;
    }

    public function getId(): ?string
    {
        return $this->response['profile:uuid'] ?? null;
    }

    public function getNickname(): ?string
    {
        return $this->response['profile:nickname'] ?? null;
    }

    public function toArray(): array
    {
        return $this->response;
    }
}