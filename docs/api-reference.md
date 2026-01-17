# API Reference

This section provides detailed API documentation for all public modules in the CapiscIO Python SDK.

## Core Exports

::: capiscio_sdk
    options:
      members:
        - secure
        - secure_agent
        - CapiscioSecurityExecutor
        - SecurityConfig
        - SimpleGuard
        - validate_agent_card
        - verify_badge
        - parse_badge
        - request_badge
        - BadgeClaims
        - TrustLevel
      show_root_heading: false

## Configuration

::: capiscio_sdk.config
    options:
      members:
        - SecurityConfig
        - DownstreamConfig
        - UpstreamConfig
      show_root_heading: false

## Trust Badge API

::: capiscio_sdk.badge
    options:
      members:
        - verify_badge
        - parse_badge
        - request_badge
        - request_badge_sync
        - request_pop_badge
        - request_pop_badge_sync
        - start_badge_keeper
        - BadgeClaims
        - VerifyOptions
        - VerifyResult
        - VerifyMode
        - TrustLevel
      show_root_heading: false

## Badge Keeper

::: capiscio_sdk.badge_keeper
    options:
      members:
        - BadgeKeeper
        - BadgeKeeperConfig
      show_root_heading: false

## Domain Validation (DV) API

::: capiscio_sdk.dv
    options:
      members:
        - create_dv_order
        - get_dv_order
        - finalize_dv_order
        - DVOrder
        - DVGrant
      show_root_heading: false

## RPC Client

### CapiscioRPCClient

::: capiscio_sdk._rpc.client.CapiscioRPCClient
    options:
      show_root_heading: true
      members:
        - connect
        - close
        - badge
        - did
        - mcp
        - scoring
        - simpleguard

### MCPClient (RFC-006 / RFC-007)

::: capiscio_sdk._rpc.client.MCPClient
    options:
      show_root_heading: true
      members:
        - evaluate_tool_access
        - verify_server_identity
        - parse_server_identity_http
        - parse_server_identity_jsonrpc
        - health

### BadgeClient

::: capiscio_sdk._rpc.client.BadgeClient
    options:
      show_root_heading: true
      members:
        - sign_badge
        - verify_badge
        - verify_badge_with_options
        - parse_badge
        - request_badge
        - request_pop_badge
        - start_keeper
        - create_dv_order
        - get_dv_order
        - finalize_dv_order

### DIDClient

::: capiscio_sdk._rpc.client.DIDClient
    options:
      show_root_heading: true
      members:
        - parse
        - new_agent_did
        - new_capiscio_agent_did
        - document_url
        - is_agent_did

### ScoringClient

::: capiscio_sdk._rpc.client.ScoringClient
    options:
      show_root_heading: true
      members:
        - score_agent_card
        - validate_rule
        - list_rule_sets
        - get_rule_set
        - aggregate_scores

### SimpleGuardClient

::: capiscio_sdk._rpc.client.SimpleGuardClient
    options:
      show_root_heading: true
      members:
        - sign
        - verify
        - sign_attached
        - verify_attached
        - generate_key_pair
        - load_key
        - export_key
        - get_key_info

## Validators

### Core Validator (Go-backed)

::: capiscio_sdk.validators._core
    options:
      members:
        - CoreValidator
        - validate_agent_card
      show_root_heading: false

### Message Validator

::: capiscio_sdk.validators.message
    options:
      show_root_heading: false

### Protocol Validator

::: capiscio_sdk.validators.protocol
    options:
      show_root_heading: false

### URL Security Validator

::: capiscio_sdk.validators.url_security
    options:
      show_root_heading: false

### Certificate Validator

::: capiscio_sdk.validators.certificate
    options:
      show_root_heading: false

### Agent Card Validator

::: capiscio_sdk.validators.agent_card
    options:
      show_root_heading: false

## Types

::: capiscio_sdk.types
    options:
      show_root_heading: false

## Errors

::: capiscio_sdk.errors
    options:
      show_root_heading: false
