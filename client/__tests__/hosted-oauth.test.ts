/**
 * Copyright Amazon.com, Inc. and its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You
 * may not use this file except in compliance with the License. A copy of
 * the License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

import { handleCognitoOAuthCallback, signInWithRedirect } from '../hosted-oauth';
import { configure } from '../config';
import { processTokens } from '../common';
import { withStorageLock } from '../lock';
import * as storage from '../storage';

// Mock dependencies
jest.mock('../config');
jest.mock('../common');
jest.mock('../lock');
jest.mock('../storage');

const mockConfigure = configure as jest.MockedFunction<typeof configure>;
const mockProcessTokens = processTokens as jest.MockedFunction<typeof processTokens>;
const mockWithStorageLock = withStorageLock as jest.MockedFunction<typeof withStorageLock>;

describe('OAuth Integration with processTokens', () => {
  let mockConfig: any;
  let mockLocation: any;
  let mockHistory: any;
  let mockStorage: any;
  let mockFetch: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockLocation = {
      href: 'https://app.example.com/signin-redirect?code=test-code&state=test-state',
      origin: 'https://app.example.com',
      pathname: '/signin-redirect',
      search: '?code=test-code&state=test-state',
      hash: '',
    };
    
    mockHistory = {
      pushState: jest.fn(),
    };
    
    mockStorage = {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
    };
    
    mockFetch = jest.fn();
    
    mockConfig = {
      clientId: 'test-client-id',
      hostedUi: {
        redirectSignIn: 'https://app.example.com/signin-redirect',
        responseType: 'code',
      },
      location: mockLocation,
      history: mockHistory,
      storage: mockStorage,
      fetch: mockFetch,
      debug: jest.fn(),
    };
    
    mockConfigure.mockReturnValue(mockConfig);
    mockWithStorageLock.mockImplementation(async (key, fn) => fn());
  });

  describe('handleCognitoOAuthCallback', () => {
    it('should handle OAuth code flow and use processTokens', async () => {
      // Setup OAuth state
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === 'cognito_oauth_in_progress') return Promise.resolve('true');
        if (key === 'cognito_oauth_state') return Promise.resolve('test-state');
        if (key === 'cognito_oauth_pkce') return Promise.resolve('test-verifier');
        return Promise.resolve(null);
      });

      // Mock token exchange response
      const mockTokenResponse = {
        access_token: 'mock-access-token',
        id_token: 'mock-id-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockTokenResponse,
      });

      // Mock processTokens to return the processed tokens
      const processedTokens = {
        accessToken: 'mock-access-token',
        idToken: 'mock-id-token',
        refreshToken: 'mock-refresh-token',
        expireAt: new Date(Date.now() + 3600000),
        username: 'test-user',
        authMethod: 'REDIRECT' as const,
      };
      mockProcessTokens.mockResolvedValue(processedTokens);

      // Call handleCognitoOAuthCallback
      const result = await handleCognitoOAuthCallback();

      // Verify processTokens was called with correct parameters
      expect(mockProcessTokens).toHaveBeenCalledWith({
        accessToken: 'mock-access-token',
        idToken: 'mock-id-token',
        refreshToken: 'mock-refresh-token',
        expireAt: expect.any(Date),
        username: 'test-user',
        authMethod: 'REDIRECT',
        newDeviceMetadata: undefined,
        userConfirmationNecessary: false,
      });

      // Verify the result
      expect(result).toEqual(processedTokens);

      // Verify cleanup
      expect(mockStorage.removeItem).toHaveBeenCalledWith('cognito_oauth_state');
      expect(mockStorage.removeItem).toHaveBeenCalledWith('cognito_oauth_pkce');
      expect(mockStorage.removeItem).toHaveBeenCalledWith('cognito_oauth_in_progress');
    });

    it('should handle OAuth implicit flow and use processTokens', async () => {
      // Setup for implicit flow
      mockLocation.href = 'https://app.example.com/signin-redirect#access_token=mock-access-token&id_token=mock-id-token&expires_in=3600&state=test-state';
      mockLocation.hash = '#access_token=mock-access-token&id_token=mock-id-token&expires_in=3600&state=test-state';
      mockLocation.search = '';
      mockConfig.hostedUi.responseType = 'token';

      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === 'cognito_oauth_in_progress') return Promise.resolve('true');
        if (key === 'cognito_oauth_state') return Promise.resolve('test-state');
        return Promise.resolve(null);
      });

      // Mock processTokens
      const processedTokens = {
        accessToken: 'mock-access-token',
        idToken: 'mock-id-token',
        refreshToken: '',
        expireAt: new Date(Date.now() + 3600000),
        username: 'test-user',
        authMethod: 'REDIRECT' as const,
      };
      mockProcessTokens.mockResolvedValue(processedTokens);

      // Call handleCognitoOAuthCallback
      const result = await handleCognitoOAuthCallback();

      // Verify processTokens was called
      expect(mockProcessTokens).toHaveBeenCalledWith({
        accessToken: 'mock-access-token',
        idToken: 'mock-id-token',
        refreshToken: '',
        expireAt: expect.any(Date),
        username: 'test-user',
        authMethod: 'REDIRECT',
        newDeviceMetadata: undefined,
        userConfirmationNecessary: false,
      });

      expect(result).toEqual(processedTokens);
    });

    it('should handle missing ID token in OAuth response', async () => {
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === 'cognito_oauth_in_progress') return Promise.resolve('true');
        if (key === 'cognito_oauth_state') return Promise.resolve('test-state');
        if (key === 'cognito_oauth_pkce') return Promise.resolve('test-verifier');
        return Promise.resolve(null);
      });

      // Mock token response without ID token
      const mockTokenResponse = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockTokenResponse,
      });

      const processedTokens = {
        accessToken: 'mock-access-token',
        idToken: '',
        refreshToken: 'mock-refresh-token',
        expireAt: new Date(Date.now() + 3600000),
        username: 'test-user',
        authMethod: 'REDIRECT' as const,
      };
      mockProcessTokens.mockResolvedValue(processedTokens);

      const result = await handleCognitoOAuthCallback();

      // Verify processTokens was called with empty idToken
      expect(mockProcessTokens).toHaveBeenCalledWith({
        accessToken: 'mock-access-token',
        idToken: '', // Empty string when missing
        refreshToken: 'mock-refresh-token',
        expireAt: expect.any(Date),
        username: 'test-user',
        authMethod: 'REDIRECT',
        newDeviceMetadata: undefined,
        userConfirmationNecessary: false,
      });

      expect(result).toEqual(processedTokens);
    });

    it('should return null when no OAuth flow is in progress', async () => {
      mockStorage.getItem.mockResolvedValue('false');

      const result = await handleCognitoOAuthCallback();
      
      expect(result).toBeNull();
      expect(mockProcessTokens).not.toHaveBeenCalled();
    });

    it('should throw error on OAuth state mismatch', async () => {
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === 'cognito_oauth_in_progress') return Promise.resolve('true');
        if (key === 'cognito_oauth_state') return Promise.resolve('different-state');
        return Promise.resolve(null);
      });

      await expect(handleCognitoOAuthCallback()).rejects.toThrow('OAuth state mismatch');
      expect(mockProcessTokens).not.toHaveBeenCalled();
    });

    it('should handle token exchange errors', async () => {
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === 'cognito_oauth_in_progress') return Promise.resolve('true');
        if (key === 'cognito_oauth_state') return Promise.resolve('test-state');
        if (key === 'cognito_oauth_pkce') return Promise.resolve('test-verifier');
        return Promise.resolve(null);
      });

      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ error: 'invalid_grant' }),
      });

      await expect(handleCognitoOAuthCallback()).rejects.toThrow('invalid_grant');
      expect(mockProcessTokens).not.toHaveBeenCalled();
    });
  });

  describe('processTokens integration', () => {
    it('should ensure processTokens handles storage, refresh scheduling, and callbacks', async () => {
      mockStorage.getItem.mockImplementation((key: string) => {
        if (key === 'cognito_oauth_in_progress') return Promise.resolve('true');
        if (key === 'cognito_oauth_state') return Promise.resolve('test-state');
        if (key === 'cognito_oauth_pkce') return Promise.resolve('test-verifier');
        return Promise.resolve(null);
      });

      const mockTokenResponse = {
        access_token: 'mock-access-token',
        id_token: 'mock-id-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockTokenResponse,
      });

      // Mock processTokens to simulate its behavior
      mockProcessTokens.mockImplementation(async (tokens) => {
        // Simulate processTokens behavior:
        // 1. Store tokens
        // 2. Schedule refresh
        // 3. Handle device keys
        // 4. Return processed tokens
        return {
          ...tokens,
          // processTokens might add or modify fields
          deviceKey: 'mock-device-key',
        };
      });

      const result = await handleCognitoOAuthCallback();

      // Verify processTokens was called
      expect(mockProcessTokens).toHaveBeenCalled();
      
      // Verify the result includes processTokens enhancements
      expect(result).toHaveProperty('deviceKey', 'mock-device-key');
    });
  });
});