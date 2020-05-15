{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Lib
  ( startApp,
  )
where

import API
import Crypto.JOSE.JWA.JWS (Alg (..))
import Crypto.JOSE.JWK (fromOctets)
import Crypto.JWT (StringOrURI)
import Data.Aeson
import Data.List (find)
import Data.Map as M hiding (map)
import Data.Proxy
import qualified Network.HTTP.Client as HTTP
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.Wai
import Network.Wai.Handler.Warp
import Servant as S
import Servant.Auth as SA
import Servant.Auth.Server as SAS
import System.IO hiding (readFile)
import Types

port :: Int
port = 3001

api :: Proxy (API '[JWT])
api = Proxy

initConnPool :: IO (Pool Connection)
initConnPool =
  pure $
    fromList
      [ (("user1", "pass1"), JWTUser "email@email.com"),
        (("user2", "pass2"), JWTUser "test@test.com")
      ]

-- get the trusted audience values from some config
intendedAudience :: [StringOrURI]
intendedAudience = ["audience-1-here", "audience-2-here"]

matchAudience :: [StringOrURI] -> StringOrURI -> IsMatch
matchAudience trustedAudiences aud = case find (== aud) trustedAudiences of
  Just _ -> Matches
  Nothing -> DoesNotMatch

mkApp :: Pool Connection -> Context '[CookieSettings, JWTSettings] -> CookieSettings -> JWTSettings -> Application
mkApp connPool cfg cookieSettings jwtCfg = serveWithContext api cfg (server connPool cookieSettings jwtCfg)

startApp :: IO ()
startApp = do
  jsonJwk <- fetchKey
  connPool <- initConnPool
  case fromJSON <$> decode jsonJwk of
    Just (Success jwkset) -> do
      let jwk = fromOctets jsonJwk
      let jwtCfg = JWTSettings jwk (Just RS256) jwkset (matchAudience intendedAudience)
          cfg = defaultCookieSettings :. jwtCfg :. EmptyContext
      let settings =
            setPort port $
              setBeforeMainLoop
                (hPutStrLn stderr ("listening on port " ++ show port))
                defaultSettings
      runSettings settings $ mkApp connPool cfg defaultCookieSettings jwtCfg
    Just (Error e) -> putStrLn e
    Nothing -> return ()
  where
    -- we don't pull the keys periodically :(
    fetchKey = do
      manager <- HTTP.newManager tlsManagerSettings
      request <- HTTP.parseRequest "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
      response <- HTTP.httpLbs request manager
      return $ HTTP.responseBody response
