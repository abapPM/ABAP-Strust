CLASS /apmg/cl_strust DEFINITION
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

    CONSTANTS c_version TYPE string VALUE '2.3.0' ##NEEDED.

    CONSTANTS:
      BEGIN OF c_context,
        prog TYPE psecontext VALUE 'PROG', " Namespace of transaction STRUST
        smim TYPE psecontext VALUE 'SMIM', " Namespace of table STRUSTSMIM
        ssfa TYPE psecontext VALUE 'SSFA', " Namespace of table SSFARGS (SSFAPPLIC)
        ssfv TYPE psecontext VALUE 'SSFV', " Namespace of table SSFVKEYDEF
        sslc TYPE psecontext VALUE 'SSLC', " Namespace of table STRUSTSSL
        ssls TYPE psecontext VALUE 'SSLS', " Namespace of table STRUSTSSLS
        wsse TYPE psecontext VALUE 'WSSE', " Namespace of table STRUSTWSSE
      END OF c_context,
      BEGIN OF c_context_description,
        prog TYPE ddtext VALUE 'System PSE',
        smim TYPE ddtext VALUE 'SMIME Standard',
        ssfa TYPE ddtext VALUE 'SSF',
        ssfv TYPE ddtext VALUE 'SSF Key Versions',
        sslc TYPE ddtext VALUE 'SSL Client',
        ssls TYPE ddtext VALUE 'SSL Server',
        wsse TYPE ddtext VALUE 'Web Service Security',
      END OF c_context_description,
      BEGIN OF c_application,
        syst   TYPE ssfappl VALUE '<SYST>', " PROG
        sncs   TYPE ssfappl VALUE '<SNCS>', " PROG
        file   TYPE ssfappl VALUE '<FILE>', " PROG
        ssls   TYPE ssfappl VALUE '<SSLS>', " PROG
        spki   TYPE ssfappl VALUE '<SPKI>', " SSLC
        dfault TYPE ssfappl VALUE 'DFAULT', " SSLC,SSLS,WSSE,SMIM
        anonym TYPE ssfappl VALUE 'ANONYM', " SSLC
        sapsup TYPE ssfappl VALUE 'SAPSUP', " SSLC
        wsscrt TYPE ssfappl VALUE 'WSSCRT', " WSSE
        wsskey TYPE ssfappl VALUE 'WSSKEY', " WSSE
      END OF c_application,
      BEGIN OF c_application_description,
        syst   TYPE ddtext VALUE 'System PSE',
        sncs   TYPE ddtext VALUE 'SNC SAP Cryptolib',
        file   TYPE ddtext VALUE 'Files',
        ssls   TYPE ddtext VALUE 'SSL backward compatibility',
        spki   TYPE ddtext VALUE 'System PKI',
        dfault TYPE ddtext VALUE 'SSL Client/Server, WSS, SMIME: Standard',
        anonym TYPE ddtext VALUE 'SSL Client: Anonymous',
        sapsup TYPE ddtext VALUE 'SSL Client: SAP Support Portal',
        wsse   TYPE ddtext VALUE 'SSL Client: Web Service Security Test',
        wsscrt TYPE ddtext VALUE 'Other System Encryption Certificates',
        wsskey TYPE ddtext VALUE 'WS Security Keys',
      END OF c_application_description.

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
      ty_certattr_tt TYPE STANDARD TABLE OF ty_certattr WITH KEY subject issuer serialno validfrom validto,
      BEGIN OF ty_update_result,
        added   TYPE ty_certattr_tt,
        removed TYPE ty_certattr_tt,
      END OF ty_update_result.

    CLASS-METHODS create
      IMPORTING
        !context      TYPE psecontext
        !application  TYPE ssfappl
        !password     TYPE string OPTIONAL
      RETURNING
        VALUE(result) TYPE REF TO /apmg/cl_strust
      RAISING
        /apmg/cx_error.

    METHODS constructor
      IMPORTING
        !context     TYPE psecontext
        !application TYPE ssfappl
        !password    TYPE string OPTIONAL
      RAISING
        /apmg/cx_error.

    METHODS load
      IMPORTING
        !create       TYPE abap_bool DEFAULT abap_false
        !id           TYPE ssfid OPTIONAL
        !org          TYPE string OPTIONAL
      RETURNING
        VALUE(result) TYPE REF TO /apmg/cl_strust
      RAISING
        /apmg/cx_error.

    METHODS add
      IMPORTING
        !certificate  TYPE ty_certificate
      RETURNING
        VALUE(result) TYPE REF TO /apmg/cl_strust
      RAISING
        /apmg/cx_error.

    METHODS add_pem
      IMPORTING
        !pem          TYPE string
      RETURNING
        VALUE(result) TYPE REF TO /apmg/cl_strust
      RAISING
        /apmg/cx_error.

    METHODS get_own_certificate
      RETURNING
        VALUE(result) TYPE ty_certattr
      RAISING
        /apmg/cx_error.

    METHODS get_certificate_list
      RETURNING
        VALUE(result) TYPE ty_certattr_tt
      RAISING
        /apmg/cx_error.

    METHODS remove
      IMPORTING
        !subject      TYPE string
        !comment      TYPE string OPTIONAL
      RETURNING
        VALUE(result) TYPE REF TO /apmg/cl_strust
      RAISING
        /apmg/cx_error.

    METHODS update
      IMPORTING
        !comment        TYPE string OPTIONAL
        !remove_expired TYPE abap_bool DEFAULT abap_false
          PREFERRED PARAMETER comment
      RETURNING
        VALUE(result)   TYPE ty_update_result
      RAISING
        /apmg/cx_error.

    CLASS-METHODS f4_context
      RETURNING
        VALUE(result) TYPE psecontext.

    CLASS-METHODS f4_application
      RETURNING
        VALUE(result) TYPE ssfappl.

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
      certs_removed TYPE ty_certattr_tt,
      cert_current  TYPE ty_certattr,
      certs_current TYPE ty_certattr_tt,
      logs          TYPE STANDARD TABLE OF /apmg/strust_log WITH KEY timestamp counter,
      is_dirty      TYPE abap_bool.

    METHODS _create
      IMPORTING
        !id  TYPE ssfid OPTIONAL
        !org TYPE string OPTIONAL
      RAISING
        /apmg/cx_error.

    METHODS _lock
      RAISING
        /apmg/cx_error.

    METHODS _profile
      RAISING
        /apmg/cx_error.

    METHODS _unlock
      RAISING
        /apmg/cx_error.

    METHODS _save
      RAISING
        /apmg/cx_error.

    METHODS _log_add
      IMPORTING
        !subject   TYPE ty_certattr-subject
        !issuer    TYPE ty_certattr-issuer
        !date_from TYPE ty_certattr-date_from
        !date_to   TYPE ty_certattr-date_to
        !status    TYPE /apmg/strust_log-status
        !message   TYPE /apmg/strust_log-message
      RAISING
        /apmg/cx_error.

    METHODS _log_save
      IMPORTING
        !comment TYPE string
      RAISING
        /apmg/cx_error.

ENDCLASS.



CLASS /apmg/cl_strust IMPLEMENTATION.


  METHOD add.

    DATA cert_new TYPE ty_certattr.

    CONCATENATE LINES OF certificate INTO DATA(certb64).
    CONDENSE certb64 NO-GAPS.

    " Remove Header and Footer
    TRY.
        FIND REGEX '-{5}.{0,}BEGIN.{0,}-{5}(.*)-{5}.{0,}END.{0,}-{5}' IN certb64 SUBMATCHES DATA(base64) ##REGEX_POSIX.
        IF sy-subrc = 0.
          ASSIGN base64 TO FIELD-SYMBOL(<data>).
          ASSERT sy-subrc = 0.
        ELSE.
          RAISE EXCEPTION TYPE /apmg/cx_error_text EXPORTING text = 'Inconsistent certificate format'(010).
        ENDIF.
      CATCH cx_sy_regex_too_complex.
        " e.g. multiple PEM frames in file
        RAISE EXCEPTION TYPE /apmg/cx_error_text EXPORTING text = 'Inconsistent certificate format'(010).
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
          RAISE EXCEPTION TYPE /apmg/cx_error_t100.
        ENDIF.

        cert_new-date_from = cert_new-validfrom(8).
        cert_new-date_to   = cert_new-validto(8).
        APPEND cert_new TO certs_new.

      CATCH cx_abap_x509_certificate.
        _unlock( ).
        RAISE EXCEPTION TYPE /apmg/cx_error_t100.
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

    DATA profile TYPE localfile.

    me->context = context.
    me->applic  = application.
    profilepw   = password.

    CALL FUNCTION 'SSFPSE_FILENAME'
      EXPORTING
        context       = context
        applic        = applic
      IMPORTING
        psename       = psename
        psetext       = psetext
        distrib       = distrib
        profile       = profile
      EXCEPTIONS
        pse_not_found = 1
        OTHERS        = 2.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE /apmg/cx_error_t100.
    ENDIF.

    me->profile = profile.

  ENDMETHOD.


  METHOD create.

    result = NEW #(
      context     = context
      application = application
      password    = password ).

  ENDMETHOD.


  METHOD f4_application.

    TYPES:
      BEGIN OF ty_value,
        field TYPE ssfappl,
        text  TYPE ddtext,
      END OF ty_value,
      ty_values TYPE STANDARD TABLE OF ty_value WITH DEFAULT KEY.

    DATA:
      value_tab  TYPE ty_values,
      return_tab TYPE STANDARD TABLE OF ddshretval WITH DEFAULT KEY.

    FIELD-SYMBOLS:
      <field>  TYPE ty_value-field,
      <text>   TYPE ty_value-text,
      <value>  LIKE LINE OF value_tab,
      <return> LIKE LINE OF return_tab.

    DO.
      ASSIGN COMPONENT sy-index OF STRUCTURE c_application TO <field>.
      IF sy-subrc <> 0.
        EXIT.
      ENDIF.
      ASSIGN COMPONENT sy-index OF STRUCTURE c_application_description TO <text>.
      IF sy-subrc <> 0.
        EXIT.
      ENDIF.
      APPEND INITIAL LINE TO value_tab ASSIGNING <value>.
      <value>-field = <field>.
      <value>-text  = <text>.
    ENDDO.

    CALL FUNCTION 'F4IF_INT_TABLE_VALUE_REQUEST'
      EXPORTING
        retfield        = 'FIELD'
        window_title    = 'Application'
        value_org       = 'S' "single
      TABLES
        value_tab       = value_tab
        return_tab      = return_tab
      EXCEPTIONS
        parameter_error = 1
        no_values_found = 2
        OTHERS          = 3 ##NO_TEXT.
    CHECK sy-subrc = 0.

    READ TABLE return_tab ASSIGNING <return> INDEX 1.
    IF sy-subrc = 0.
      result = <return>-fieldval.
    ENDIF.

  ENDMETHOD.


  METHOD f4_context.

    TYPES:
      BEGIN OF ty_value,
        field TYPE psecontext,
        text  TYPE ddtext,
      END OF ty_value,
      ty_values TYPE STANDARD TABLE OF ty_value WITH DEFAULT KEY.

    DATA:
      value_tab  TYPE ty_values,
      return_tab TYPE STANDARD TABLE OF ddshretval WITH DEFAULT KEY.

    FIELD-SYMBOLS:
      <field>  TYPE ty_value-field,
      <text>   TYPE ty_value-text,
      <value>  LIKE LINE OF value_tab,
      <return> LIKE LINE OF return_tab.

    DO.
      ASSIGN COMPONENT sy-index OF STRUCTURE c_context TO <field>.
      IF sy-subrc <> 0.
        EXIT.
      ENDIF.
      ASSIGN COMPONENT sy-index OF STRUCTURE c_context_description TO <text>.
      IF sy-subrc <> 0.
        EXIT.
      ENDIF.
      APPEND INITIAL LINE TO value_tab ASSIGNING <value>.
      <value>-field = <field>.
      <value>-text  = <text>.
    ENDDO.

    CALL FUNCTION 'F4IF_INT_TABLE_VALUE_REQUEST'
      EXPORTING
        retfield        = 'FIELD'
        window_title    = 'Context'
        value_org       = 'S' "single
      TABLES
        value_tab       = value_tab
        return_tab      = return_tab
      EXCEPTIONS
        parameter_error = 1
        no_values_found = 2
        OTHERS          = 3 ##NO_TEXT.
    CHECK sy-subrc = 0.

    READ TABLE return_tab ASSIGNING <return> INDEX 1.
    IF sy-subrc = 0.
      result = <return>-fieldval.
    ENDIF.

  ENDMETHOD.


  METHOD get_certificate_list.

    DATA:
      certlist    TYPE ssfbintab,
      certificate TYPE ty_certattr.

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
      RAISE EXCEPTION TYPE /apmg/cx_error_t100.
    ENDIF.

    LOOP AT certlist ASSIGNING FIELD-SYMBOL(<certlist>).

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
        RAISE EXCEPTION TYPE /apmg/cx_error_t100.
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
      RAISE EXCEPTION TYPE /apmg/cx_error_t100.
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
      RAISE EXCEPTION TYPE /apmg/cx_error_t100.
    ENDIF.

    cert_current-date_from = cert_current-validfrom(8).
    cert_current-date_to   = cert_current-validto(8).

    result = cert_current.

  ENDMETHOD.


  METHOD load.

    CLEAR: is_dirty, certs_removed, certs_current.

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
        file_write_failed = 3
        OTHERS            = 4.
    IF sy-subrc <> 0.
      IF create = abap_true.
        _create(
          id  = id
          org = org ).
      ELSE.
        RAISE EXCEPTION TYPE /apmg/cx_error_t100.
      ENDIF.
    ENDIF.

    result = me.

  ENDMETHOD.


  METHOD remove.

    _profile( ).

    " Remove certificates
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
        RAISE EXCEPTION TYPE /apmg/cx_error_t100.
      ENDIF.

      _log_add(
        subject   = <cert>-subject
        issuer    = <cert>-issuer
        date_from = <cert>-date_from
        date_to   = <cert>-date_to
        status    = icon_led_green
        message   = 'Removed' ).

      is_dirty = abap_true.

    ENDLOOP.

    _save( ).

    _log_save( comment ).

    result = me.

  ENDMETHOD.


  METHOD update.

    CLEAR certs_removed.

    _profile( ).

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
              RAISE EXCEPTION TYPE /apmg/cx_error_t100.
            ENDIF.

            " Track removed certificate
            APPEND <cert> TO certs_removed.

            _log_add(
              subject   = <cert>-subject
              issuer    = <cert>-issuer
              date_from = <cert>-date_from
              date_to   = <cert>-date_to
              status    = icon_led_green
              message   = 'Removed' ).

            is_dirty = abap_true.
          ELSE.
            " Certificate already exists, no update necessary
            DELETE certs_new INDEX tabix.
          ENDIF.

        ENDLOOP.

      ENDLOOP.
    ENDIF.

    " Add new certificates
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

      IF sy-subrc = 5.
        " SAP message is misleading so use a better text
        _unlock( ).
        RAISE EXCEPTION TYPE /apmg/cx_error_text
          EXPORTING
            text = |Certificate { <cert_new>-subject } already exists|.
      ELSEIF sy-subrc <> 0.
        _unlock( ).
        RAISE EXCEPTION TYPE /apmg/cx_error_t100.
      ENDIF.

      _log_add(
        subject   = <cert_new>-subject
        issuer    = <cert_new>-issuer
        date_from = <cert_new>-date_from
        date_to   = <cert_new>-date_to
        status    = icon_led_green
        message   = 'Added' ).

      is_dirty = abap_true.

    ENDLOOP.

    _save( ).

    _log_save( comment ).

    result-added   = certs_new.
    result-removed = certs_removed.

  ENDMETHOD.


  METHOD _create.

    DATA:
      license_num TYPE c LENGTH 10,
      new_id      TYPE ssfid,
      subject     TYPE certsubjct,
      psepath     TYPE trfile.

    " Create new PSE (using RSA-SHA256 2048 which is the default in STRUST in recent releases)
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

    REPLACE '%SID' IN new_id WITH sy-sysid.
    REPLACE '%LIC' IN new_id WITH license_num.
    REPLACE '%ORG' IN new_id WITH org.
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
      RAISE EXCEPTION TYPE /apmg/cx_error_t100.
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
      RAISE EXCEPTION TYPE /apmg/cx_error_t100.
    ENDIF.

  ENDMETHOD.


  METHOD _log_add.

    DATA(log) = VALUE /apmg/strust_log(
      cert_subject = subject
      cert_issues  = issuer
      date_from    = date_from
      date_to      = date_to
      status       = status
      message      = message ).

    INSERT log INTO TABLE logs.

  ENDMETHOD.


  METHOD _log_save.

    GET TIME STAMP FIELD DATA(timestamp).

    LOOP AT logs ASSIGNING FIELD-SYMBOL(<log>).
      <log>-timestamp = timestamp.
      <log>-counter   = sy-tabix.
      <log>-username  = sy-uname.
      <log>-comments  = comment.
    ENDLOOP.

    INSERT /apmg/strust_log FROM TABLE @logs.
    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE /apmg/cx_error_text EXPORTING text = 'Error saving comments to log table'(012).
    ENDIF.

  ENDMETHOD.


  METHOD _profile.

    IF tempfile IS NOT INITIAL.
      profile = tempfile.
    ENDIF.

    IF profile IS INITIAL.
      RAISE EXCEPTION TYPE /apmg/cx_error_text EXPORTING text = 'Missing profile. Call "load" first'(011).
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
      RAISE EXCEPTION TYPE /apmg/cx_error_t100.
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

    _unlock( ).

  ENDMETHOD.


  METHOD _unlock.

    " Drop temporary file
    TRY.
        DELETE DATASET tempfile.
      CATCH cx_sy_file_open.
        RAISE EXCEPTION TYPE /apmg/cx_error_text
          EXPORTING
            text = 'Error deleting file'(020) && | { tempfile }|.
      CATCH cx_sy_file_authority.
        RAISE EXCEPTION TYPE /apmg/cx_error_text
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
      RAISE EXCEPTION TYPE /apmg/cx_error_t100.
    ENDIF.

  ENDMETHOD.
ENDCLASS.
