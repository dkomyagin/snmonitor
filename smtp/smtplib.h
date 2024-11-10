//======================================================================================
// Name        : smtplib.h
// Author      : Dmitry Komyagin
// Version     : 1.0
// Created on  : Oct 29, 2024
// Copyright   : Public domain
// Description : Header file for SMTP embedded client library
//======================================================================================

#ifndef SMTPLIB_H_
#define SMTPLIB_H_

#define SMTP_LIB_CLASS_MAILER "smtpMailer"
// Methods
#define SMTP_LIB_MAILER_METHOD_CONSTRUCTOR      "smtpMailer()"
#define SMTP_LIB_MAILER_METHOD_SENDER           "Sender()"
#define SMTP_LIB_MAILER_METHOD_HANDLER          "mailHandler()"
#define SMTP_LIB_MAILER_METHOD_SENDMAIL         "sendMail()"
#define SMTP_LIB_MAILER_METHOD_ONSENDERROR      "onSendError()"

#define SMTP_LIB_CLASS_STD_CONNECTION "smtpConnection"
// Methods
#define SMTP_LIB_STD_CONN_METHOD_OPEN_SD        "openSocket()"
#define SMTP_LIB_STD_CONN_METHOD_SETUP_CONN     "setupConnection()"
#define SMTP_LIB_STD_CONN_METHOD_SEND_CMD_STD   "sendCmd_std()"
#define SMTP_LIB_STD_CONN_METHOD_SEND_EHLO_STD  "sendEHLO_std()"
#define SMTP_LIB_STD_CONN_METHOD_SEND_QUIT_STD  "sendQUIT_std()"
#define SMTP_LIB_STD_CONN_METHOD_OPEN_CONN      "openConnection()"

#define SMTP_LIB_CLASS_SMTP_TLS_SSL "smtpTLS_SSL"
// Methods
#define SMTP_LIB_TLSSSL_METHOD_CONNECT_SSL      "connectSSL()"
#define SMTP_LIB_TLSSSL_METHOD_SRV_RESPONSE     "readSrvResponse()"
#define SMTP_LIB_TLSSSL_METHOD_SEND_CMD_TLS     "sendCmd_tls()"
#define SMTP_LIB_TLSSSL_METHOD_SEND_EHLO_TLS    "sendEHLO_tls()"
#define SMTP_LIB_TLSSSL_METHOD_SEND_QUIT_TLS    "sendQUIT_tls()"
#define SMTP_LIB_TLSSSL_METHOD_AUTH             "Authenticate()"

#define SMTP_LIB_CLASS_TLS_CONNECTION "smtpConnection_TLS"
// Methods
#define SMTP_LIB_TLSSSL_METHOD_OPEN_SMTPS       "openSMTPS()"
#define SMTP_LIB_TLSSSL_METHOD_OPEN_CONN        "openConnection()"

// Informer message type
#define SMTP_LIB_SMTP_TLS_SRV_REPLY              7
#define SMTP_LIB_SMTP_TLS_COMMAND                6
#define SMTP_LIB_SMTP_SRV_REPLY                  5
#define SMTP_LIB_SMTP_COMMAND                    4
#define SMTP_LIB_SETUP_SUCCESS                   3
#define SMTP_LIB_HANDLER_STOPPED                 2
#define SMTP_LIB_SENT_OK                         1

#define SMTP_LIB_DEBUG                           0

#define SMTP_LIB_CHANNEL_ERROR                  -1
#define SMTP_LIB_SERVER_ERROR                   -2
#define SMTP_LIB_SENDER_ADDR_INVALID            -3
#define SMTP_LIB_SENDER_ADDR_UNKNOWN            -4
#define SMTP_LIB_SENDER_ADDR_UNALLOWED          -5
#define SMTP_LIB_SENDER_ADDR_INVALID_FOR_LOGIN  -6
#define SMTP_LIB_SENDER_ADDR_NOT_ACCEPTED       -7
#define SMTP_LIB_SENDER_ADDR_ERROR              -8
#define SMTP_LIB_MB_SYNTAX_ERROR                -9
#define SMTP_LIB_MB_UNAVAILABLE                 -10
#define SMTP_LIB_MB_INVALID                     -11
#define SMTP_LIB_MB_NOT_ALLOWED                 -12
#define SMTP_LIB_UNABLE_FRWD                    -13
#define SMTP_LIB_RCPNT_NOT_ACCEPTED             -14
#define SMTP_LIB_RCPNT_ADDR_ERROR               -15
#define SMTP_LIB_NO_VALID_RCPNTS                -16
#define SMTP_LIB_RESEND_TIMEOUT_EXCEEDED        -17
#define SMTP_LIB_TRANSMISSION_ERROR             -18
#define SMTP_LIB_RESET_ERROR                    -19
#define SMTP_LIB_FAILED_TO_CONNECT              -20
#define SMTP_LIB_CONNECTION_SETUP_ERROR         -21
#define SMTP_LIB_SOCKET_ERROR                   -22
#define SMTP_LIB_CONNECTION_ERROR               -23
#define SMTP_LIB_SSLTLS_SETUP_ERROR             -24
#define SMTP_LIB_SSLTLS_CONNECTION_ERROR        -25
#define SMTP_LIB_SSLTLS_SRV_VERIFICATION_ERROR  -26
#define SMTP_LIB_SSLTLS_AUTH_METHOD_ERROR       -27
#define SMTP_LIB_SSLTLS_AUTH_FAILED             -28
#define SMTP_LIB_SEND_TIMEOUT_EXCEEDED          -29
#define SMTP_LIB_ERROR_SOCKET                   -30
#define SMTP_LIB_ERROR_TO_OPTION                -31
#define SMTP_LIB_ERROR_GET_OWN_HOSTNAME         -32
#define SMTP_LIB_ERROR_DNS_RESOLUTION           -33
#define SMTP_LIB_TCP_SEND_ERROR                 -34
#define SMTP_LIB_TCP_READ_ERROR                 -35
#define SMTP_LIB_FAILED_TO_GET_SRV_RESPONSE     -36
#define SMTP_LIB_TLS_SEND_ERROR                 -37
#define SMTP_LIB_TLS_READ_ERROR                 -38
#define SMTP_LIB_TLS_NOT_SUPPORTED              -39

#endif /* SMTPLIB_H_ */
