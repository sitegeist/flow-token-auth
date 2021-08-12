<?php
namespace Flownative\TokenAuthentication\Security;

use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;

/**
 * A Flow security token that authenticates based on a hash delivered.
 */
class HashToken extends AbstractToken
{
    /**
     * @var array
     */
    protected $credentials;

    /**
     * @param ActionRequest $actionRequest
     * @return bool
     * @throws InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        $authenticationHashToken = $actionRequest->getHttpRequest()->getQueryParams()['_authenticationHashToken'] ?? null;
        
        
        if(substr($actionRequest->getHttpRequest()->getHeader('Authorization')[0],0,5) === 'Basic') {
            return false;
        }

        if (!$authenticationHashToken) {            
            //temporarily bypass the htaccess authentification
            if(isset($actionRequest->getHttpRequest()->getHeader('Authorization')[0])) {
                if(substr($actionRequest->getHttpRequest()->getHeader('Authorization')[0],0,5) === 'Basic') {
                    return false;
                }
            }
            
            $authorizationHeader = $actionRequest->getHttpRequest()->getHeader('Authorization');
            if ($authorizationHeader) {
                $authenticationHashToken = str_replace('Bearer ', '', $authorizationHeader);
            }
        }

        if ($authenticationHashToken) {
            $this->credentials['password'] = $authenticationHashToken;
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        }

        return false;
    }
}
