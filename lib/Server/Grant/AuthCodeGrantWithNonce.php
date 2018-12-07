<?php
/**
 */

namespace  SimpleSAML\Modules\OpenIDConnect\Server\Grant;

use DateInterval;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;

class AuthCodeGrantWithNonce extends AuthCodeGrant
{
    private $nonce;

    /**
     * {@inheritdoc}
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request)
    {
        $this->nonce = $this->getQueryStringParameter('nonce', $request);
        return parent::validateAuthorizationRequest($request);
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    )
    {
        $encryptedAuthCode = $this->getRequestParameter('code', $request, null);
        if ($encryptedAuthCode === null) {
            throw OAuthServerException::invalidRequest('code');
        }

        try {
            $authCodePayload = json_decode($this->decrypt($encryptedAuthCode));

            $authCode = $this->authCodeRepository->findById($authCodePayload->auth_code_id);
            $this->nonce = $authCode->getNonce();
        } catch (LogicException $e) {
            throw OAuthServerException::invalidRequest('code', 'Cannot decrypt the authorization code', $e);
        }

        return parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
    }

    /**
     * {@inheritdoc}
     */
    protected function issueAuthCode(
        DateInterval $authCodeTTL,
        ClientEntityInterface $client,
        $userIdentifier,
        $redirectUri,
        array $scopes = []
    )
    {
        $authCode = parent::issueAuthCode($authCodeTTL, $client, $userIdentifier, $redirectUri, $scopes);

        if (!empty($this->nonce)) {
            $authCode->setNonce($this->nonce);
            $this->authCodeRepository->update($authCode);
        }

        return $authCode;
    }

    /**
     * {@inheritdoc}
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        $userIdentifier,
        array $scopes = []
    ) {
        $accessToken = parent::issueAccessToken($accessTokenTTL, $client, $userIdentifier, $scopes);

        if (!empty($this->nonce)) {
            $accessToken->setNonce($this->nonce);
            $this->accessTokenRepository->update($accessToken);
        }

        return $accessToken;
    }
}
