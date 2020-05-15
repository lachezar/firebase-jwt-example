{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TypeOperators #-}

module Types
  ( JWTUser (..),
    API,
    Pool,
    Connection,
    PublicAPI,
    PublicHandler,
    PrivateAPI,
    PrivateHandler,
  )
where

import Control.Monad.Trans.Reader
import Data.Map
import Data.Text (Text)
import GHC.Generics
import Servant as S
import Servant.Auth.Server as SAS

type Login = String

type Password = String

type DB = Map (Login, Password) JWTUser

type Connection = DB

type Pool a = a

newtype JWTUser = JWTUser {juEmail :: Text} deriving (Show, Generic)

type API auths =
  (SAS.Auth auths JWTUser :> PrivateAPI)
    :<|> PublicAPI

type PublicAPI = "public" :> Capture "n" Int :> Get '[JSON] [JWTUser]

type PublicHandler a = ReaderT (Pool Connection) S.Handler a

type PrivateAPI = "private" :> Capture "n" Int :> Get '[JSON] [JWTUser]

type PrivateHandler a = ReaderT (Pool Connection, JWTUser) S.Handler a
