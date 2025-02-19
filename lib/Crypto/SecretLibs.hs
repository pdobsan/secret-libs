{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.SecretLibs
  ( decryptFile,
    encryptFile,
    lookupSecret,
    storeSecret,
    SecretToolsError (..),
  )
where

import Crypto.Gpgme
import Data.ByteString qualified as BS
import Data.ByteString.UTF8 qualified as BSU
import Data.Map qualified as Map
import Data.Maybe
import Data.Text qualified as Text
import GI.Gio qualified as Gio
import GI.Secret.Functions qualified as GIS
import System.Directory qualified as D
import System.Environment
import Text.Printf (printf)

type KeyID = String

type Secret = String

data SecretToolsError
  = FileError String
  | DecryptError String
  | EncryptError String
  | LookupError String
  | StoreError String
  deriving (Show)

decryptFile :: FilePath -> IO (Either SecretToolsError Secret)
decryptFile f = do
  fOk <- D.doesFileExist f
  if fOk
    then do
      gpgHome <- getEnv "HOME" >>= \x -> pure (x ++ "/.gnupg")
      enc <- BS.readFile f
      withCtx gpgHome "C" OpenPGP $ \ctx ->
        decrypt ctx enc
          >>= \case
            Left err -> return $ Left $ DecryptError (show err)
            Right o -> return $ Right (BSU.toString o)
    else pure $ Left $ FileError $ printf "Can't open file: %s\n" f

encryptFile :: FilePath -> Secret -> KeyID -> IO (Either SecretToolsError String)
encryptFile f s k = do
  gpgHome <- getEnv "HOME" >>= \x -> pure (x ++ "/.gnupg")
  withCtx gpgHome "C" OpenPGP $ \ctx -> do
    key <- getKey ctx (BSU.fromString k) NoSecret
    encrypt ctx [fromJust key] NoFlag (BSU.fromString s)
      >>= \case
        Right enc -> do
          BS.writeFile f enc
          pure $ Right "gpg encryption succeded."
        Left err -> return $ Left $ EncryptError (show err)

type Attribute = String

type Value = String

type Label = String

lookupSecret :: Attribute -> Value -> IO (Either SecretToolsError String)
lookupSecret attribute value = do
  GIS.passwordLookupSync
    Nothing
    (Map.fromList [(Text.pack attribute, Text.pack value)])
    (Nothing @Gio.Cancellable)
    >>= \case
      Just o -> return $ Right (Text.unpack o)
      Nothing ->
        return $
          Left $
            LookupError $
              printf "Can't find secret associated with %s %s\n" attribute value

storeSecret :: Label -> Attribute -> Value -> Secret -> IO (Either SecretToolsError String)
storeSecret label attribute value secret = do
  -- TODO check retun status
  _ <-
    GIS.passwordStoreSync
      Nothing
      (Map.fromList [(Text.pack attribute, Text.pack value)])
      Nothing
      (Text.pack label)
      (Text.pack secret)
      (Nothing @Gio.Cancellable)
  return $ Right "storing secret succeded."
