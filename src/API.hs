{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module API where

import Control.Lens hiding (Context)
import Control.Monad.Trans.Reader
import qualified Crypto.JWT as Jose
import Data.Aeson
import qualified Data.HashMap.Strict as HM
import Data.List (isSuffixOf)
import Data.Map as M hiding (map)
import Data.Proxy
import Data.Text (pack)
import Servant as S
import Servant.Auth.Server as SAS
import Types (API, Connection, JWTUser, JWTUser (..), Pool, PrivateAPI, PrivateHandler, PublicAPI, PublicHandler)

instance ToJSON JWTUser

instance FromJSON JWTUser

instance ToJWT JWTUser

instance FromJWT JWTUser where
  -- decodeJWT :: Jose.ClaimsSet -> Either Text a
  decodeJWT m = case (HM.lookup "email" uc, HM.lookup "email_verified" uc) of
    (Nothing, _) -> Left "Missing 'email' in the user claims"
    (_, Nothing) -> Left "The email in the user claims is not verified"
    (Just v1, Just v2) -> case (fromJSON v1, fromJSON v2) of
      (Error e, _) -> Left $ pack e
      (_, Error e) -> Left $ pack e
      (Success _, Success False) -> Left "The email in the user claims is not verified"
      (Success email, Success True) ->
        if not $ any (`isSuffixOf` email) allowedEmails
          then Left "Invalid 'email' in the user claims"
          else Right $ JWTUser $ pack email
    where
      uc = m ^. Jose.unregisteredClaims

-- read the allowed email suffixes from configuration
allowedEmails :: [String]
allowedEmails = ["@test.com", "@email.com"]

server :: Pool Connection -> CookieSettings -> JWTSettings -> Server (API auths)
server connPool _ _ = privateServer connPool :<|> publicServer connPool

publicApi :: Proxy PublicAPI
publicApi = Proxy

publicServer :: Pool Connection -> Server PublicAPI
publicServer connPool = hoistServer publicApi (`runReaderT` connPool) getPublic

privateApi :: Proxy PrivateAPI
privateApi = Proxy

privateServer :: Pool Connection -> SAS.AuthResult JWTUser -> ServerT PrivateAPI Handler
privateServer connPool (SAS.Authenticated user) = hoistServer privateApi (privateUserHook connPool user) getUsers
privateServer _ _ = throwAll err401

privateUserHook :: Pool Connection -> JWTUser -> PrivateHandler a -> Handler a
privateUserHook connPool user handler = runReaderT handler (connPool, user)

getUsers :: Int -> PrivateHandler [JWTUser]
getUsers _ = do
  (connPool, _) <- ask
  return $ map snd $ toList connPool

getPublic :: Int -> PublicHandler [JWTUser]
getPublic _ = map snd . toList <$> ask
