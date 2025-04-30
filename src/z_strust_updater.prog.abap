REPORT z_strust_updater LINE-SIZE 255.

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
  SELECT-OPTIONS:
    so_subj FOR ('STRING') NO INTERVALS.
SELECTION-SCREEN END OF BLOCK b2.

SELECTION-SCREEN BEGIN OF BLOCK b3 WITH FRAME TITLE TEXT-t03.
  PARAMETERS:
    p_days   TYPE i DEFAULT 30,
    p_passwd TYPE string LOWER CASE,
    p_test   AS CHECKBOX DEFAULT 'X'.
SELECTION-SCREEN END OF BLOCK b3.

START-OF-SELECTION.

  DATA(strust) = zcl_strust2=>create(
    context     = p_cont
    application = p_appl
    password    = p_passwd ).

  DATA(certs) = strust->load( )->get_certificate_list( ).

  SORT certs BY date_to date_from.

  LOOP AT certs ASSIGNING FIELD-SYMBOL(<cert>) WHERE subject IN so_subj.

    DATA(days_until_expire) = <cert>-date_to - sy-datum.

    WRITE: / <cert>-subject,
      AT 130 |{ <cert>-date_from DATE = ISO }|,
      AT 145 |{ <cert>-date_to DATE = ISO }|,
      AT 158 ''.

    IF days_until_expire > 30.
      WRITE: 'valid' COLOR COL_POSITIVE.
    ELSEIF days_until_expire > 7.
      WRITE: 'expires in a month' COLOR COL_TOTAL.
    ELSEIF days_until_expire > 0.
      WRITE: 'expires in a week' COLOR COL_GROUP.
    ELSE.
      WRITE: 'expired' COLOR COL_NEGATIVE.
    ENDIF.

    IF days_until_expire <= p_days.
    ENDIF.

  ENDLOOP.
