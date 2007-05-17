#include <PAM.h>
#include <string>
#include <iostream>

namespace PAM {
    Exception::Exception(pam_handle_t* _pamh,
               const std::string& _func_name,
               int _errnum):
        errnum(_errnum),
        errstr(pam_strerror(_pamh, _errnum)),
        func_name(_func_name)
        {};

    Auth_Exception::Auth_Exception(pam_handle_t* _pamh,
                                   const std::string& _func_name,
                                   int _errnum):
        Exception(_pamh, _func_name, _errnum){};

    Cred_Exception::Cred_Exception(pam_handle_t* _pamh,
                                   const std::string& _func_name,
                                   int _errnum):
        Exception(_pamh, _func_name, _errnum){};

    int Authenticator::_end(void){
        int result=pam_end(pamh, last_result);
        pamh=0;
        return result;
    };

    Authenticator::Authenticator(conversation* conv, void* data):pamh(0){
        pam_conversation.conv=conv;
        pam_conversation.appdata_ptr=data;
    };

    Authenticator::~Authenticator(void){
        if (pamh) _end();
    };

    void Authenticator::start(const std::string& service){
        switch((last_result=pam_start(service.c_str(), NULL, &pam_conversation, &pamh))){
            default:
                throw Exception(pamh, "pam_start()", last_result);

            case PAM_SUCCESS:
                break;
        }
        return;
    }

    void Authenticator::end(void){
        switch((last_result=_end())){
            default:
                throw Exception(pamh, "pam_end()", last_result);

            case PAM_SUCCESS:
                break;

        }
        return;
    };

    void Authenticator::set_item(const Authenticator::ItemType item, const void* value){
        switch((last_result=pam_set_item(pamh, item, value))){
            default:
            _end();
                throw Exception(pamh, "pam_set_item()", last_result);

            case PAM_SUCCESS:
                break;
        }
        return;
    }

    const void* Authenticator::get_item(const Authenticator::ItemType item){
        const void* data;
        switch ((last_result=pam_get_item(pamh, item, &data))){
            default:
            case PAM_SYSTEM_ERR:
            case PAM_BAD_ITEM:
                _end();
                throw Exception(pamh, "pam_get_item()", last_result);

            case PAM_PERM_DENIED: // The value of item was NULL
            case PAM_SUCCESS:
                break;
        }
        return data;
    };

    void Authenticator::fail_delay(const unsigned int micro_sec){
        switch((last_result=pam_fail_delay(pamh, micro_sec))){
            default:
                _end();
                throw Exception(pamh, "fail_delay()", last_result);

            case PAM_SUCCESS:
                break;
        }
        return;
    };

    void Authenticator::authenticate(void){
        switch((last_result=pam_authenticate(pamh, 0))){
            default:
            case PAM_ABORT:
            case PAM_AUTHINFO_UNAVAIL:
                _end();
                throw Exception(pamh, "pam_authenticate()", last_result);

            case PAM_USER_UNKNOWN:
            case PAM_MAXTRIES:
            case PAM_CRED_INSUFFICIENT:
            case PAM_AUTH_ERR:
                throw Auth_Exception(pamh, "pam_authentication()", last_result);

            case PAM_SUCCESS:
                break;
        }

        switch((last_result=pam_acct_mgmt(pamh, PAM_SILENT))){
            default:
            //case PAM_NEW_AUTHTOKEN_REQD:
            case PAM_ACCT_EXPIRED:
            case PAM_USER_UNKNOWN:
                _end();
                throw Exception(pamh, "pam_acct_mgmt()", last_result);
                
            case PAM_AUTH_ERR:
            case PAM_PERM_DENIED:
                throw Auth_Exception(pamh, "pam_acct_mgmt()", last_result);

            case PAM_SUCCESS:
                break;
        };
        return;
    };

    void Authenticator::open_session(void){
        switch((last_result=pam_setcred(pamh, PAM_ESTABLISH_CRED))){
            default:
            case PAM_CRED_ERR:
            case PAM_CRED_UNAVAIL:
                _end();
                throw Exception(pamh, "pam_setcred()", last_result);

            case PAM_CRED_EXPIRED:
            case PAM_USER_UNKNOWN:
                throw Cred_Exception(pamh, "pam_setcred()", last_result);

            case PAM_SUCCESS:
                break;
        }

        switch((last_result=pam_open_session(pamh, 0))){
            default:
            //case PAM_SESSION_ERROR:
                pam_setcred(pamh, PAM_DELETE_CRED);
                _end();
                throw Exception(pamh, "pam_open_session()", last_result);

            case PAM_SUCCESS:
                break;
        };
        return;
    };

    void Authenticator::close_session(void){
        switch((last_result=pam_close_session(pamh, 0))){
            default:
            //case PAM_SESSION_ERROR:
                pam_setcred(pamh, PAM_DELETE_CRED);
                _end();
                throw Exception(pamh, "pam_close_session", last_result);

            case PAM_SUCCESS:
                break;
        };
        switch((last_result=pam_setcred(pamh, PAM_DELETE_CRED))){
            default:
            case PAM_CRED_ERR:
            case PAM_CRED_UNAVAIL:
            case PAM_CRED_EXPIRED:
            case PAM_USER_UNKNOWN:
                _end();
                throw Exception(pamh, "pam_setcred()", last_result);

            case PAM_SUCCESS:
                break;
        }
        return;
    };

    void Authenticator::setenv(const std::string& key, const std::string& value){
        std::string name_value = key+"="+value;
        switch((last_result=pam_putenv(pamh, name_value.c_str()))){
            default:
            case PAM_PERM_DENIED:
            case PAM_BAD_ITEM:
            case PAM_ABORT:
            case PAM_BUF_ERR:
                _end();
                throw Exception(pamh, "pam_putenv()", last_result);

            case PAM_SUCCESS:
                break;
        };
        return;
    };

    void Authenticator::delenv(const std::string& key){
        switch((last_result=pam_putenv(pamh, key.c_str()))){
            default:
            case PAM_PERM_DENIED:
            case PAM_BAD_ITEM:
            case PAM_ABORT:
            case PAM_BUF_ERR:
                _end();
                throw Exception(pamh, "pam_putenv()", last_result);

            case PAM_SUCCESS:
                break;
        };
        return;
    };

    const char* Authenticator::getenv(const std::string& key){
        return pam_getenv(pamh, key.c_str());
    };

    char** Authenticator::getenvlist(void){
        return pam_getenvlist(pamh);
    };

};

std::ostream& operator<<( std::ostream& os, const PAM::Exception& e){
    os << e.func_name << ": " << e.errstr;
    return os;
};
