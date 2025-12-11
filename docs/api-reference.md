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
      show_root_heading: false

## Configuration

::: capiscio_sdk.config
    options:
      members:
        - SecurityConfig
        - DownstreamConfig
        - UpstreamConfig
      show_root_heading: false

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
