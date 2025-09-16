REPORT /apmg/strust_updater LINE-SIZE 255.

************************************************************************
* Trust Management: Certificate Updater
*
* Copyright 2025 apm.to Inc. <https://apm.to>
* SPDX-License-Identifier: MIT
************************************************************************

SELECTION-SCREEN BEGIN OF BLOCK b1 WITH FRAME TITLE TEXT-t01.
  PARAMETERS:
    p_cont TYPE psecontext DEFAULT 'SSLC' OBLIGATORY,
    p_appl TYPE ssfappl DEFAULT 'ANONYM' OBLIGATORY.
SELECTION-SCREEN END OF BLOCK b1.

SELECTION-SCREEN BEGIN OF BLOCK b2 WITH FRAME TITLE TEXT-t02.
  SELECT-OPTIONS s_subj FOR ('STRING') NO INTERVALS.
  SELECTION-SCREEN SKIP.
  PARAMETERS p_text TYPE string LOWER CASE.
SELECTION-SCREEN END OF BLOCK b2.

SELECTION-SCREEN BEGIN OF BLOCK b4 WITH FRAME TITLE TEXT-t04.
  PARAMETERS:
    p_ssl_id TYPE ssfappl DEFAULT 'ANONYM',
    p_host   TYPE string OBLIGATORY LOWER CASE,
    p_endpnt TYPE string OBLIGATORY LOWER CASE.
SELECTION-SCREEN END OF BLOCK b4.

SELECTION-SCREEN BEGIN OF BLOCK b3 WITH FRAME TITLE TEXT-t03.
  PARAMETERS:
    p_days   TYPE i DEFAULT 30,
    p_passwd TYPE string LOWER CASE,
    p_root   AS CHECKBOX DEFAULT abap_true,
    p_main   AS CHECKBOX DEFAULT abap_true,
    p_remove AS CHECKBOX DEFAULT abap_true,
    p_test   AS CHECKBOX DEFAULT abap_true.
SELECTION-SCREEN END OF BLOCK b3.

INITIALIZATION.

  DATA(subrc) = cl_abap_pse=>authority_check( iv_activity = '01' )
    + cl_abap_pse=>authority_check( iv_activity = '02' )
    + cl_abap_pse=>authority_check( iv_activity = '06' ).
  IF subrc <> 0.
    MESSAGE 'You are not authorized to update certificates' TYPE 'I' DISPLAY LIKE 'E'.
    STOP.
  ENDIF.

  p_host   = /apmg/cl_strust_cert_api=>c_api_host.
  p_endpnt = /apmg/cl_strust_cert_api=>c_api_endpoint.

START-OF-SELECTION.

  IF p_root IS INITIAL AND p_main IS INITIAL.
    MESSAGE 'No certificates selected for update' TYPE 'I' DISPLAY LIKE 'E'.
    STOP.
  ENDIF.

  CALL FUNCTION 'SSFPSE_PARAMETER'
    EXPORTING
      context       = p_cont
      applic        = p_appl
    EXCEPTIONS
      pse_not_found = 1
      OTHERS        = 2.
  IF sy-subrc <> 0.
    MESSAGE 'PSE not found' TYPE 'I' DISPLAY LIKE 'E'.
    STOP.
  ENDIF.

  TRY.
      DATA(strust) = /apmg/cl_strust=>create(
        context     = p_cont
        application = p_appl
        password    = p_passwd )->load( ).

      DATA(certs) = strust->get_certificate_list( ).
    CATCH /apmg/cx_error INTO DATA(error).
      MESSAGE error TYPE 'I' DISPLAY LIKE 'E'.
      STOP.
  ENDTRY.

  SORT certs BY date_to date_from.

  LOOP AT certs ASSIGNING FIELD-SYMBOL(<cert>) WHERE subject IN s_subj.

    DATA(days_until_expire) = <cert>-date_to - sy-datum.

    WRITE: / <cert>-subject,
      AT 130 |{ <cert>-date_from DATE = ISO }|,
      AT 145 |{ <cert>-date_to DATE = ISO }|,
      AT 158 ''.

    IF days_until_expire > 30.
      WRITE 'valid' COLOR COL_POSITIVE.
    ELSEIF days_until_expire > 7.
      WRITE 'expires in a month' COLOR COL_TOTAL.
    ELSEIF days_until_expire > 0.
      WRITE 'expires in a week' COLOR COL_GROUP.
    ELSE.
      WRITE 'expired' COLOR COL_NEGATIVE.
    ENDIF.

    IF days_until_expire > p_days.
      CONTINUE.
    ENDIF.

    " Get the domain of the certificate
    DATA(dn) = /apmg/cl_distinguished_name=>parse( <cert>-subject ).

    IF NOT line_exists( dn[ key = 'CN' ] ).
      WRITE /5 'Unable to determine CN of certificate subject' COLOR COL_NEGATIVE.
      ULINE.
      CONTINUE.
    ENDIF.

    DATA(domain) = dn[ key = 'CN' ]-name.

    IF domain NA '.'.
      " It's probably a root or intermediate certificate
      " Go to their website to
      WRITE /5 'Unable to determine domain of certificate' COLOR COL_TOTAL.
      ULINE.
      CONTINUE.
    ENDIF.

    WRITE: /5 'Domain:', domain COLOR COL_POSITIVE.
    SKIP.

    TRY.
        DATA(json) = /apmg/cl_strust_cert_api=>get_certificates(
          ssl_id   = p_ssl_id
          domain   = domain
          host     = p_host
          endpoint = p_endpnt ).

        TRY.
            DATA(ajson) = zcl_ajson=>parse( json ).
          CATCH zcx_ajson_error INTO DATA(ajson_error).
            WRITE: /10 'Error parsing API response:' COLOR COL_NEGATIVE, ajson_error->get_text( ).
            ULINE.
            CONTINUE.
        ENDTRY.

        IF ajson->get( '/error' ) IS NOT INITIAL.
          WRITE: /10 'Error getting certificates from API:' COLOR COL_NEGATIVE, ajson->get( '/error' ).
          ULINE.
          CONTINUE.
        ENDIF.

        " Keep fingers crossed that the response matches what we need for the update
        DATA(cert_domain) = ajson->get( '/domain' ).

        IF cert_domain <> domain AND domain NA '*'.
          WRITE: /10 'Certificates domain does not match request:' COLOR COL_TOTAL, cert_domain.
          ULINE.
          CONTINUE.
        ENDIF.

        " We finally have a certificate that can be used for the update, yay!
        " Root and intermediate certificates
        IF p_root = abap_true.

          LOOP AT ajson->members( '/intermediateCertificates' ) INTO DATA(member).

            DATA(inter_pem)       = ajson->get( '/intermediateCertificates/' && member && '/pem' ).
            DATA(inter_date_from) = ajson->get( '/intermediateCertificates/' && member && '/validFrom' ).
            DATA(inter_date_to)   = ajson->get( '/intermediateCertificates/' && member && '/validTo' ).
            DATA(inter_subject)   = 'CN=' && ajson->get( '/intermediateCertificates/' && member && '/subject/CN' ).
            IF inter_subject = 'CN='.
              inter_subject = 'O=' && ajson->get( '/intermediateCertificates/' && member && '/subject/O' ).
            ENDIF.
            IF strlen( inter_subject ) > 78.
              inter_subject = inter_subject(75) && '...'.
            ENDIF.

            IF p_test = abap_false.
              strust->add_pem( inter_pem ).
            ENDIF.

            WRITE: /10 'Root/intermediate certificate added:' COLOR COL_POSITIVE,
              AT 50 inter_subject,
              AT 130 inter_date_from(10),
              AT 145 inter_date_to(10),
              AT 158 ''.

          ENDLOOP.
          SKIP.

        ENDIF.

        " Domain certificate
        IF p_main = abap_true.

          DATA(peer_pem)       = ajson->get( '/peerCertificate/pem' ).
          DATA(peer_date_from) = ajson->get( '/peerCertificate/validFrom' ).
          DATA(peer_date_to)   = ajson->get( '/peerCertificate/validTo' ).
          DATA(peer_subject)   = 'CN=' && ajson->get( '/peerCertificate/subject/CN' ).
          IF peer_subject = 'CN='.
            peer_subject = 'O=' && ajson->get( '/peerCertificate/subject/O' ).
          ENDIF.
          IF strlen( peer_subject ) > 78.
            peer_subject = peer_subject(75) && '...'.
          ENDIF.

          IF p_test = abap_false.
            strust->add_pem( peer_pem ).
          ENDIF.

          WRITE: /10 'New certificate added' COLOR COL_POSITIVE,
            AT 50 peer_subject,
            AT 130 peer_date_from(10),
            AT 145 peer_date_to(10),
            AT 158 ''.

        ENDIF.

      CATCH /apmg/cx_error INTO error.
        WRITE: /10 'Error updating certificate:' COLOR COL_NEGATIVE, error->get_text( ).
    ENDTRY.

    ULINE.
  ENDLOOP.

  IF sy-subrc <> 0.
    WRITE / 'No certificates found' COLOR COL_TOTAL.
    STOP.
  ENDIF.

  ULINE.

  IF p_test = abap_true.
    WRITE: / 'Test run' COLOR COL_TOTAL, '(changes were not saved)'.
    STOP.
  ENDIF.

  " Save changes
  TRY.
      strust->update(
        comment        = p_text
        remove_expired = p_remove ).

      WRITE / 'Certificates saved' COLOR COL_POSITIVE.

      IF p_remove = abap_true.
        DATA(logs) TYPE STANDARD TABLE OF /apmg/strust_log WITH DEFAULT KEY.
        logs = strust->get_logs( ).

        DATA(removed_count) = 0.

        LOOP AT logs ASSIGNING FIELD-SYMBOL(<log>) WHERE message = 'Removed'.
          IF removed_count = 0.
            SKIP.
            WRITE / 'Certificates removed:' COLOR COL_TOTAL.
          ENDIF.
          removed_count += 1.
          WRITE: /5 <log>-cert_subject,
            AT 130 |{ <log>-date_from DATE = ISO }|,
            AT 145 |{ <log>-date_to DATE = ISO }|,
            AT 158 ''.
        ENDLOOP.

        IF removed_count = 0.
          SKIP.
          WRITE / 'No expired certificates were removed' COLOR COL_TOTAL.
        ENDIF.
      ENDIF.
    CATCH /apmg/cx_error INTO error.
      WRITE: / 'Error updating certificate:' COLOR COL_NEGATIVE, error->get_text( ).
  ENDTRY.
