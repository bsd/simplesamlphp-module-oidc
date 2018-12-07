<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Entity;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\MementoInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Traits\RevokeTokenTrait;
use SimpleSAML\Modules\OpenIDConnect\Utils\TimestampGenerator;

class AccessTokenEntity implements AccessTokenEntityInterface, MementoInterface
{
    use AccessTokenTrait, TokenEntityTrait, EntityTrait, RevokeTokenTrait;

    private $nonce;

    private function __construct()
    {
    }

    public function getNonce() {
        return $this->nonce;
    }

    public function setNonce($nonce) {
        $this->nonce = $nonce;
        return $this;
    }

    /**
     * Create new Access Token from data.
     *
     * @param ClientEntityInterface      $clientEntity
     * @param array|ScopeEntityInterface $scopes
     * @param string|null                $userIdentifier
     *
     * @return AccessTokenEntity
     */
    public static function fromData(ClientEntityInterface $clientEntity, array $scopes, string $userIdentifier = null)
    {
        $accessToken = new self();

        $accessToken->setClient($clientEntity);
        $accessToken->setUserIdentifier($userIdentifier);
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        return $accessToken;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromState(array $state)
    {
        $accessToken = new self();

        $scopes = array_map(function ($scope) {
            return ScopeEntity::fromData($scope);
        }, json_decode($state['scopes'], true));

        $accessToken->identifier = $state['id'];
        $accessToken->scopes = $scopes;
        $accessToken->expiryDateTime = TimestampGenerator::utc($state['expires_at']);
        $accessToken->userIdentifier = $state['user_id'];
        $accessToken->client = $state['client'];
        $accessToken->isRevoked = (bool) $state['is_revoked'];

        if (isset($state['nonce'])) {
            $accessToken->setNonce($state['nonce']);
        }

        return $accessToken;
    }

    /**
     * {@inheritdoc}
     */
    public function getState(): array
    {
        return [
            'id' => $this->identifier,
            'scopes' => json_encode($this->scopes),
            'expires_at' => $this->expiryDateTime->format('Y-m-d H:i:s'),
            'user_id' => $this->userIdentifier,
            'client_id' => $this->client->getIdentifier(),
            'is_revoked' => $this->isRevoked,
            'nonce' => $this->nonce,
        ];
    }
}
