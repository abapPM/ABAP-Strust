CLASS zcl_strust2 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

************************************************************************
* Trust Management
*
* Add, update, or remove certificates from ABAP Trust Management
*
* Copyright 2024 apm.to Inc. <https://apm.to>
* SPDX-License-Identifier: MIT
************************************************************************
  PUBLIC SECTION.

    CONSTANTS c_version TYPE string VALUE '2.0.0' ##NEEDED.

    CONSTANTS:
      BEGIN OF c_context ##NEEDED,
        prog TYPE psecontext VALUE 'PROG', " Namespace of transaction STRUST
        smim TYPE psecontext VALUE 'SMIM', " Namespace of table STRUSTSMIM
        ssfa TYPE psecontext VALUE 'SSFA', " Namespace of table SSFARGS
        ssfv TYPE psecontext VALUE 'SSFV', " Namespace of table SSFVKEYDEF
        sslc TYPE psecontext VALUE 'SSLC', " Namespace of table STRUSTSSL
        ssls TYPE psecontext VALUE 'SSLS', " Namespace of table STRUSTSSLS
        wsse TYPE psecontext VALUE 'WSSE', " Namespace of table STRUSTWSSE
      END OF c_context,
      BEGIN OF c_application ##NEEDED,
        syst   TYPE ssfappl VALUE '<SYST>', " PROG:            System PSE
        sncs   TYPE ssfappl VALUE '<SNCS>', " PROG:            SNC SAP Cryptolib
        file   TYPE ssfappl VALUE '<FILE>', " PROG:            Files
        ssls   TYPE ssfappl VALUE '<SSLS>', " PROG:            SSL backward compatibility
        spki   TYPE ssfappl VALUE '<SPKI>', " SSLC:            System PKI
        dfault TYPE ssfappl VALUE 'DFAULT', " SSLC,SSLS,WSSE:  SSL Client/Server: Standard
        anonym TYPE ssfappl VALUE 'ANONYM', " SSLC:            SSL Client: Anonymous
        sapsup TYPE ssfappl VALUE 'SAPSUP', " SSLC:            SSL Client: SAP Support Portal
        wsse   TYPE ssfappl VALUE 'WSSE',   " WSSE:            SSL Client: Web Service Security
        wsscrt TYPE ssfappl VALUE 'WSSCRT', " WSSE:            Other System Encryption Certificates
        wwkey  TYPE ssfappl VALUE 'WSSKEY', " WSSE:            WS Security Keys
      END OF c_application.

    TYPES:
      ty_line        TYPE c LENGTH 80,
      ty_certificate TYPE STANDARD TABLE OF ty_line WITH KEY table_line,
      BEGIN OF ty_certattr,
        subject     TYPE string,
        issuer      TYPE string,
        serialno    TYPE string,
        validfrom   TYPE string,
        validto     TYPE string,
        date_from   TYPE d,
        date_to     TYPE d,
        certificate TYPE xstring,
      END OF ty_certattr,
      ty_certattr_tt TYPE STANDARD TABLE OF ty_certattr WITH KEY subject issuer serialno validfrom validto.

    CLASS-METHODS create
      IMPORTING
        !context      TYPE psecontext
        !application  TYPE ssfappl
        !password     TYPE string OPTIONAL
      RETURNING
        VALUE(result) TYPE REF TO zcl_strust2
      RAISING
        zcx_error.

    METHODS constructor
      IMPORTING
        !context     TYPE psecontext
        !application TYPE ssfappl
        !password    TYPE string OPTIONAL
      RAISING
        zcx_error.

    METHODS load
      IMPORTING
        !create       TYPE abap_bool DEFAULT abap_false
        !id           TYPE ssfid OPTIONAL
        !org          TYPE string OPTIONAL
      RETURNING
        VALUE(result) TYPE REF TO zcl_strust2
      RAISING
        zcx_error.

    METHODS add
      IMPORTING
        !certificate  TYPE ty_certificate
      RETURNING
        VALUE(result) TYPE REF TO zcl_strust2
      RAISING
        zcx_error.

    METHODS add_pem
      IMPORTING
        !pem          TYPE string
      RETURNING
        VALUE(result) TYPE REF TO zcl_strust2
      RAISING
        zcx_error.

    METHODS get_own_certificate
      RETURNING
        VALUE(result) TYPE ty_certattr
      RAISING
        zcx_error.

    METHODS get_certificate_list
      RETURNING
        VALUE(result) TYPE ty_certattr_tt
      RAISING
        zcx_error.

    METHODS remove
      IMPORTING
        !subject      TYPE string
      RETURNING
        VALUE(result) TYPE REF TO zcl_strust2
      RAISING
        zcx_error.

    METHODS update
      IMPORTING
        !remove_expired TYPE abap_bool DEFAULT abap_false
      RETURNING
        VALUE(result)   TYPE ty_certattr_tt
      RAISING
        zcx_error.

  PROTECTED SECTION.
  PRIVATE SECTION.

    DATA:
      context       TYPE psecontext,
      applic        TYPE ssfappl,
      psename       TYPE ssfpsename,
      psetext       TYPE strustappltxt ##NEEDED,
      distrib       TYPE ssfflag,
      tempfile      TYPE localfile,
      id            TYPE ssfid,
      profile       TYPE ssfpab,
      profilepw     TYPE ssfpabpw,
      cert_own      TYPE xstring,
      certs_new     TYPE ty_certattr_tt,
      cert_current  TYPE ty_certattr,
      certs_current TYPE ty_certattr_tt,
      is_dirty      TYPE abap_bool.

    METHODS _create
      IMPORTING
        !id  TYPE ssfid OPTIONAL
        !org TYPE string OPTIONAL
      RAISING
        zcx_error.

    METHODS _lock
      RAISING
        zcx_error.

    METHODS _profile
      RAISING
        zcx_error.

    METHODS _unlock
      RAISING
        zcx_error.

    METHODS _save
      RAISING
        zcx_error.

ENDCLASS.



CLASS zcl_strust2 IMPLEMENTATION.


  METHOD add.

    DATA cert_new TYPE ty_certattr.

    CONCATENATE LINES OF certificate INTO DATA(certb64).
    CONDENSE certb64 NO-GAPS.

    " Remove Header and Footer
    TRY.
        FIND REGEX '-{5}.{0,}BEGIN.{0,}-{5}(.*)-{5}.{0,}END.{0,}-{5}' IN certb64 SUBMATCHES DATA(base64).
        IF sy-subrc = 0.
          ASSIGN base64 TO FIELD-SYMBOL(<data>).
          ASSERT sy-subrc = 0.
        ELSE.
          RAISE EXCEPTION TYPE zcx_error_text EXPORTING text = 'Inconsistent certificate format'(010).
        ENDIF.
      CATCH cx_sy_regex_too_complex.
        " e.g. multiple PEM frames in file
        RAISE EXCEPTION TYPE zcx_error_text EXPORTING text = 'Inconsistent certificate format'(010).
    ENDTRY.

    TRY.
        DATA(certobj) = NEW cl_abap_x509_certificate( <data> ).

        cert_new-certificate = certobj->get_certificate( ).

        CALL FUNCTION 'SSFC_PARSE_CERTIFICATE'
          EXPORTING
            certificate         = cert_new-certificate
          IMPORTING
            subject             = cert_new-subject
            issuer              = cert_new-issuer
            serialno            = cert_new-serialno
            validfrom           = cert_new-validfrom
            validto             = cert_new-validto
          EXCEPTIONS
            ssf_krn_error       = 1
            ssf_krn_nomemory    = 2
            ssf_krn_nossflib    = 3
            ssf_krn_invalid_par = 4
            OTHERS              = 5.
        IF sy-subrc <> 0.
          _unlock( ).
          RAISE EXCEPTION TYPE zcx_error_t100.
        ENDIF.

        cert_new-date_from = cert_new-validfrom(8).
        cert_new-date_to   = cert_new-validto(8).
        APPEND cert_new TO certs_new.

      CATCH cx_abap_x509_certificate.
        _unlock( ).
        RAISE EXCEPTION TYPE zcx_error_t100.
    ENDTRY.

    result = me.

  ENDMETHOD.


  METHOD add_pem.

    DATA certificate TYPE ty_certificate.

    SPLIT pem AT |\n| INTO TABLE certificate.

    add( certificate ).

    result = me.

  ENDMETHOD.


  METHOD constructor.

    me->context = context.
    me->applic  = application.
    profilepw   = password.

    DATA(profile_cast) = CONV localfile( profile ).

    CALL FUNCTION 'SSFPSE_FILENAME'
      EXPORTING
        context       = context
        applic        = applic
      IMPORTING
        psename       = psename
        psetext       = psetext
        distrib       = distrib
        profile       = profile_cast
      EXCEPTIONS
        pse_not_found = 1
        OTHERS        = 2.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE zcx_error_t100.
    ENDIF.

  ENDMETHOD.


  METHOD create.

    result = NEW #(
      context     = context
      application = application
      password    = password ).

  ENDMETHOD.


  METHOD get_certificate_list.

    DATA:
      certlist    TYPE ssfbintab,
      certificate TYPE ty_certattr.

    FIELD-SYMBOLS <certlist> LIKE LINE OF certlist.

    _profile( ).

    CALL FUNCTION 'SSFC_GET_CERTIFICATELIST'
      EXPORTING
        profile               = profile
        profilepw             = profilepw
      IMPORTING
        certificatelist       = certlist
      EXCEPTIONS
        ssf_krn_error         = 1
        ssf_krn_nomemory      = 2
        ssf_krn_nossflib      = 3
        ssf_krn_invalid_par   = 4
        ssf_krn_nocertificate = 5
        OTHERS                = 6.
    IF sy-subrc <> 0.
      _unlock( ).
      RAISE EXCEPTION TYPE zcx_error_t100.
    ENDIF.

    LOOP AT certlist ASSIGNING <certlist>.

      CLEAR certificate.

      CALL FUNCTION 'SSFC_PARSE_CERTIFICATE'
        EXPORTING
          certificate         = <certlist>
        IMPORTING
          subject             = certificate-subject
          issuer              = certificate-issuer
          serialno            = certificate-serialno
          validfrom           = certificate-validfrom
          validto             = certificate-validto
        EXCEPTIONS
          ssf_krn_error       = 1
          ssf_krn_nomemory    = 2
          ssf_krn_nossflib    = 3
          ssf_krn_invalid_par = 4
          OTHERS              = 5.
      IF sy-subrc <> 0.
        _unlock( ).
        RAISE EXCEPTION TYPE zcx_error_t100.
      ENDIF.

      certificate-date_from = certificate-validfrom(8).
      certificate-date_to   = certificate-validto(8).
      APPEND certificate TO certs_current.

    ENDLOOP.

    result = certs_current.

  ENDMETHOD.


  METHOD get_own_certificate.

    _profile( ).

    CALL FUNCTION 'SSFC_GET_OWNCERTIFICATE'
      EXPORTING
        profile               = profile
        profilepw             = profilepw
      IMPORTING
        certificate           = cert_own
      EXCEPTIONS
        ssf_krn_error         = 1
        ssf_krn_nomemory      = 2
        ssf_krn_nossflib      = 3
        ssf_krn_invalid_par   = 4
        ssf_krn_nocertificate = 5
        OTHERS                = 6.
    IF sy-subrc <> 0.
      _unlock( ).
      RAISE EXCEPTION TYPE zcx_error_t100.
    ENDIF.

    CALL FUNCTION 'SSFC_PARSE_CERTIFICATE'
      EXPORTING
        certificate         = cert_own
      IMPORTING
        subject             = cert_current-subject
        issuer              = cert_current-issuer
        serialno            = cert_current-serialno
        validfrom           = cert_current-validfrom
        validto             = cert_current-validto
      EXCEPTIONS
        ssf_krn_error       = 1
        ssf_krn_nomemory    = 2
        ssf_krn_nossflib    = 3
        ssf_krn_invalid_par = 4
        OTHERS              = 5.
    IF sy-subrc <> 0.
      _unlock( ).
      RAISE EXCEPTION TYPE zcx_error_t100.
    ENDIF.

    cert_current-date_from = cert_current-validfrom(8).
    cert_current-date_to   = cert_current-validto(8).

    result = cert_current.

  ENDMETHOD.


  METHOD load.

    CLEAR is_dirty.

    _lock( ).

    CALL FUNCTION 'SSFPSE_LOAD'
      EXPORTING
        psename           = psename
      IMPORTING
        id                = me->id
        fname             = tempfile
      EXCEPTIONS
        authority_missing = 1
        database_failed   = 2
        OTHERS            = 3.
    IF sy-subrc <> 0.
      IF create = abap_true.
        _create(
          id  = id
          org = org ).
      ELSE.
        RAISE EXCEPTION TYPE zcx_error_t100.
      ENDIF.
    ENDIF.

    result = me.

  ENDMETHOD.


  METHOD remove.

    " Remove certificate
    LOOP AT certs_current ASSIGNING FIELD-SYMBOL(<cert>) WHERE subject = subject.

      CALL FUNCTION 'SSFC_REMOVECERTIFICATE'
        EXPORTING
          profile               = profile
          profilepw             = profilepw
          subject               = <cert>-subject
          issuer                = <cert>-issuer
          serialno              = <cert>-serialno
        EXCEPTIONS
          ssf_krn_error         = 1
          ssf_krn_nomemory      = 2
          ssf_krn_nossflib      = 3
          ssf_krn_invalid_par   = 4
          ssf_krn_nocertificate = 5
          OTHERS                = 6.
      IF sy-subrc <> 0.
        _unlock( ).
        RAISE EXCEPTION TYPE zcx_error_t100.
      ENDIF.

      is_dirty = abap_true.

    ENDLOOP.

    _save( ).

    _unlock( ).

    result = me.

  ENDMETHOD.


  METHOD update.

    " Remove expired certificates
    IF remove_expired = abap_true.
      LOOP AT certs_current ASSIGNING FIELD-SYMBOL(<cert>).

        LOOP AT certs_new ASSIGNING FIELD-SYMBOL(<cert_new>) WHERE subject = <cert>-subject.
          DATA(tabix) = sy-tabix.

          IF <cert_new>-date_to > <cert>-date_to.
            " Certificate is newer, so remove the old certificate
            CALL FUNCTION 'SSFC_REMOVECERTIFICATE'
              EXPORTING
                profile               = profile
                profilepw             = profilepw
                subject               = <cert>-subject
                issuer                = <cert>-issuer
                serialno              = <cert>-serialno
              EXCEPTIONS
                ssf_krn_error         = 1
                ssf_krn_nomemory      = 2
                ssf_krn_nossflib      = 3
                ssf_krn_invalid_par   = 4
                ssf_krn_nocertificate = 5
                OTHERS                = 6.
            IF sy-subrc <> 0.
              _unlock( ).
              RAISE EXCEPTION TYPE zcx_error_t100.
            ENDIF.

            is_dirty = abap_true.
          ELSE.
            " Certificate already exists, no update necessary
            DELETE certs_new INDEX tabix.
          ENDIF.

        ENDLOOP.

      ENDLOOP.
    ENDIF.

    " Add new certificates to PSE
    LOOP AT certs_new ASSIGNING <cert_new>.

      CALL FUNCTION 'SSFC_PUT_CERTIFICATE'
        EXPORTING
          profile             = profile
          profilepw           = profilepw
          certificate         = <cert_new>-certificate
        EXCEPTIONS
          ssf_krn_error       = 1
          ssf_krn_nomemory    = 2
          ssf_krn_nossflib    = 3
          ssf_krn_invalid_par = 4
          ssf_krn_certexists  = 5
          OTHERS              = 6.
      IF sy-subrc <> 0.
        _unlock( ).
        RAISE EXCEPTION TYPE zcx_error_t100.
      ENDIF.

      is_dirty = abap_true.
    ENDLOOP.

    _save( ).

    _unlock( ).

    result = certs_new.

  ENDMETHOD.


  METHOD _create.

    DATA:
      license_num TYPE c LENGTH 10,
      new_id      TYPE ssfid,
      subject     TYPE certsubjct,
      psepath     TYPE trfile.

*   Create new PSE (using RSA-SHA256 2048 which is the default in STRUST in recent releases)
    IF id IS INITIAL.
      CASE applic.
        WHEN 'DFAULT'.
          new_id = `CN=%SID SSL client SSL Client (Standard), ` &&
                  `OU=I%LIC, OU=SAP Web AS, O=SAP Trust Community, C=DE` ##NO_TEXT.
        WHEN 'ANONYM'.
          new_id = 'CN=anonymous' ##NO_TEXT.
      ENDCASE.
    ELSE.
      new_id = id.
    ENDIF.

    CALL FUNCTION 'SLIC_GET_LICENCE_NUMBER'
      IMPORTING
        license_number = license_num.

    REPLACE '%SID' WITH sy-sysid INTO new_id.
    REPLACE '%LIC' WITH license_num INTO new_id.
    REPLACE '%ORG' WITH org INTO new_id.
    CONDENSE new_id.

    subject = new_id.

    CALL FUNCTION 'SSFPSE_CREATE'
      EXPORTING
        dn                = subject
        alg               = 'R'
        keylen            = 2048
      IMPORTING
        psepath           = psepath
      EXCEPTIONS
        ssf_unknown_error = 1
        OTHERS            = 2.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE zcx_error_t100.
    ENDIF.

    tempfile = psepath.

    _save( ).

  ENDMETHOD.


  METHOD _lock.

    CALL FUNCTION 'SSFPSE_ENQUEUE'
      EXPORTING
        psename         = psename
      EXCEPTIONS
        database_failed = 1
        foreign_lock    = 2
        internal_error  = 3
        OTHERS          = 4.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE zcx_error_t100.
    ENDIF.

  ENDMETHOD.


  METHOD _profile.

    IF tempfile IS NOT INITIAL.
      profile = tempfile.
    ENDIF.

    IF profile IS INITIAL.
      RAISE EXCEPTION TYPE zcx_error_text EXPORTING text = 'Missing profile. Call "load" first'(011).
    ENDIF.

  ENDMETHOD.


  METHOD _save.

    DATA cred_name TYPE icm_credname.

    CHECK is_dirty = abap_true.

    " Store PSE
    CALL FUNCTION 'SSFPSE_STORE'
      EXPORTING
        fname             = tempfile
        psepin            = profilepw
        psename           = psename
        id                = id
        b_newdn           = abap_false
        b_distribute      = distrib
      EXCEPTIONS
        file_load_failed  = 1
        storing_failed    = 2
        authority_missing = 3
        OTHERS            = 4.
    IF sy-subrc <> 0.
      _unlock( ).
      RAISE EXCEPTION TYPE zcx_error_t100.
    ENDIF.

    IF profile(3) = 'SSL'.
      cred_name = psename.

      CALL FUNCTION 'ICM_SSL_PSE_CHANGED'
        EXPORTING
          global              = 1
          cred_name           = cred_name
        EXCEPTIONS
          icm_op_failed       = 1
          icm_get_serv_failed = 2
          icm_auth_failed     = 3
          OTHERS              = 4.
      IF sy-subrc = 0.
        MESSAGE s086(trust).
      ELSE.
        MESSAGE s085(trust).
      ENDIF.
    ELSE.
      MESSAGE 'Certificate was saved successfully' TYPE 'S'.
    ENDIF.

  ENDMETHOD.


  METHOD _unlock.

    " Drop temporary file
    TRY.
        DELETE DATASET tempfile.
      CATCH cx_sy_file_open.
        RAISE EXCEPTION TYPE zcx_error_text
          EXPORTING
            text = 'Error deleting file'(020) && | { tempfile }|.
      CATCH cx_sy_file_authority.
        RAISE EXCEPTION TYPE zcx_error_text
          EXPORTING
            text = 'Not authorized to delete file'(030) && | { tempfile }|.
    ENDTRY.

    " Unlock PSE
    CALL FUNCTION 'SSFPSE_DEQUEUE'
      EXPORTING
        psename         = psename
      EXCEPTIONS
        database_failed = 1
        foreign_lock    = 2
        internal_error  = 3
        OTHERS          = 4.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE zcx_error_t100.
    ENDIF.

  ENDMETHOD.
ENDCLASS.
