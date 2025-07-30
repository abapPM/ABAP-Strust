CLASS /apmg/cl_strust_cert_api DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

************************************************************************
* Trust Management: Certificate API
*
* Get peer, intermediate, and root certificates for a domain from
* https://tools.abappm.com
*
* Copyright 2025 apm.to Inc. <https://apm.to>
* SPDX-License-Identifier: MIT
************************************************************************
  PUBLIC SECTION.

    CLASS-METHODS get_certificates
      IMPORTING
        !domain       TYPE string
        !ssl_id       TYPE ssfapplssl DEFAULT 'ANONYM'
        !debug        TYPE abap_bool DEFAULT abap_false
      RETURNING
        VALUE(result) TYPE string
      RAISING
        /apmg/cx_error.

  PROTECTED SECTION.
  PRIVATE SECTION.

    CONSTANTS:
      c_api_host     TYPE string VALUE 'https://tools.abappm.com',
      c_api_endpoint TYPE string VALUE '/api/v1/certificates'.

    CLASS-METHODS _client
      IMPORTING
        ssl_id        TYPE ssfapplssl
        uri           TYPE string
      RETURNING
        VALUE(result) TYPE REF TO if_http_client
      RAISING
        /apmg/cx_error.

    CLASS-METHODS _response
      IMPORTING
        http_client   TYPE REF TO if_http_client
      RETURNING
        VALUE(result) TYPE REF TO if_http_response
      RAISING
        /apmg/cx_error.

    CLASS-METHODS _debug
      IMPORTING
        headers TYPE tihttpnvp
        cookies TYPE tihttpcki
        debug   TYPE abap_bool ##CALLED.

ENDCLASS.



CLASS /apmg/cl_strust_cert_api IMPLEMENTATION.


  METHOD get_certificates.

    " We can't query wildcard domains so we try with "api" sub-domain
    " TODO: if this fails, loop over a couple other common sub-domains
    DATA(query) = replace( val = domain sub = '*' with = 'api' ).

    query = cl_abap_dyn_prg=>escape_xss_url( query ).

    DATA(http_client) = _client(
      ssl_id = ssl_id
      uri    = |{ c_api_endpoint }?domain={ query }| ).

    DATA(fetch_response) = _response( http_client ).

    " --- Retrieve Certificates from Response ---

    DATA(json_response) = fetch_response->get_cdata( ).

    IF debug = abap_true.
      cl_abap_browser=>show_html( html_string = json_response ).
    ENDIF.

    IF json_response IS INITIAL OR json_response(1) <> '{'.
      RAISE EXCEPTION TYPE /apmg/cx_error_text
        EXPORTING
          text = |Invalid response (expected JSON): { json_response }|.
    ENDIF.

    result = json_response.

  ENDMETHOD.


  METHOD _client.

    cl_http_client=>create_by_url(
      EXPORTING
        url    = c_api_host
        ssl_id = ssl_id
      IMPORTING
        client = result
      EXCEPTIONS
        OTHERS = 99 ).
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE /apmg/cx_error_t100.
    ENDIF.

    result->request->set_header_field(
      name  = '~request_uri'
      value = uri ).

    result->request->set_header_field(
      name  = 'accept'
      value = 'application/json' ).

  ENDMETHOD.


  METHOD _debug.

    CHECK debug = abap_true.

    DATA(html) = `<h2>Headers:</h2>\n`.
    LOOP AT headers ASSIGNING FIELD-SYMBOL(<header>).
      html = html && |<p>{ <header>-name }: { <header>-value }</p>\n|.
    ENDLOOP.

    html = html && `<h2>Cookies:</h2>\n`.
    LOOP AT cookies ASSIGNING FIELD-SYMBOL(<cookie>).
      html = html && |<p>{ <cookie>-name }: { <cookie>-value }</p>\n|.
    ENDLOOP.

    cl_abap_browser=>show_html( html_string = html ).

  ENDMETHOD.


  METHOD _response.

    DATA:
      status_code TYPE sy-subrc,
      message     TYPE string.

    http_client->propertytype_accept_cookie = if_http_client=>co_enabled.

    http_client->request->set_version( if_http_entity=>co_protocol_version_1_1 ).

    http_client->send(
      EXCEPTIONS
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3
        http_invalid_timeout       = 4
        OTHERS                     = 5 ).
    IF sy-subrc = 0.
      http_client->receive(
        EXCEPTIONS
          http_communication_failure = 1
          http_invalid_state         = 2
          http_processing_failed     = 3
          OTHERS                     = 4 ).
    ENDIF.

    IF sy-subrc <> 0.
      http_client->get_last_error(
        IMPORTING
          code    = status_code
          message = message ).
      RAISE EXCEPTION TYPE /apmg/cx_error_text EXPORTING text = |{ message } (HTTP/{ status_code })|.
    ENDIF.

    result = http_client->response.

  ENDMETHOD.
ENDCLASS.
