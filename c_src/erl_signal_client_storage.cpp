#include "erl_signal_client_storage.h"
#include "base64.h"


/** 
 * STORAGE 
 **/

esc_storage::esc_storage() {

}

esc_storage::~esc_storage() {

}

void esc_storage::set(const key key, const row row ) {
    esc_storage::storage::iterator iterator = this->data.find(key);
    if (iterator == this->data.end()) {            
        this->data[key] = row;
    } else {
        delete &iterator->second;
        iterator->second = row;
    }
    this->is_changed = true;
};

void esc_storage::erase(const key key) {
    this->data.erase(key);
    this->is_changed = true;    
};

const esc_storage::row esc_storage::get(const key key) const {
    esc_storage::storage::const_iterator iterator = this->data.find(key);
    if (iterator == this->data.end()) {
        return row();
    } else {
        return iterator->second;
    }
};

esc_storage::storage::const_iterator esc_storage::begin() const{
    return this->data.begin();
}

esc_storage::storage::const_iterator esc_storage::end() const {
    return this->data.end();
}

void esc_storage::flush() {
    this->is_changed = false;    
}

std::list <esc_storage::row> esc_storage::get_nearby(const std::string key) const {
    std::list <esc_storage::row> result;
    storage::const_iterator iterator = this->data.lower_bound(key);
    int n = key.size();
    bool flag = true;
    do {
        std::string k = iterator->first;
        k.resize(n, 0);
        if (key.compare(k) == 0) {
            result.push_front(iterator->second);
            iterator++;
        } else {
            flag = false;
        }
    } while (flag);
    return result;
}

int esc_storage::erase_nearby(const key key) {
    storage::const_iterator iterator = this->data.lower_bound(key);
    int n = key.size();
    bool flag = true;
    int counter = 0;
    do {
        std::string k = iterator->first;
        k.resize(n, 0);
        if (key.compare(k) == 0) {                   
            iterator = this->data.erase(iterator);
            counter++;
        } else {
            flag = false;
        }
    } while (flag || iterator == this->data.end());
    this->is_changed = true;    
    return counter;
}

void esc_storage::clear() {
    this->data.clear();
    this->is_changed = true;
}

bool esc_storage::is_member(const key key) const {
    return this->data.find(key) != this->data.end();
}

std::list <esc_storage::key> esc_storage::keys() const{
    std::list <key> result;
    for(storage::const_iterator it=this->data.begin();it != this->data.end();it++) {
        result.push_front(it->first);
    }
    return result;
}

/*
std::string esc_storage::serialize() {
    cJSON *json = cJSON_CreateObject();
    for(esc_storage::storage::const_iterator iterator = this->data.begin();iterator != this->data.end(); iterator++) {
        key key = base64_encode((const unsigned char *) iterator->first.c_str(), iterator->first.length());
        row value = base64_encode((const unsigned char *) iterator->second.c_str(), iterator->second.length());        
        cJSON_AddStringToObject(json, key.c_str(), value.c_str());
    }
    std::string result = cJSON_Print(json);
    cJSON_Delete(json);
    return result;
};

int esc_storage::unserialize(const std::string str) {
    cJSON *json_begin = cJSON_Parse(str.c_str());
    this->data.clear();
    for(cJSON *json = json_begin; json != NULL; json = json->next) {
        std::string key = base64_decode(std::string(json->string));
        std::string value = base64_decode(std::string(json->valuestring));
        this->data.insert(key, value);
    }
    this->is_changed = false;
    cJSON_Delete(json_begin);
    return 0;
};
*/


/**
 * ROW 
 **/
void esc_storage::row::store(const column column, const value value) {
    row_map::iterator iterator = this->data.find(column);
    if (iterator == this->data.end()) {            
        this->data[column] = value;
    } else {
        delete &iterator->second;
        iterator->second = value;
    }
};

int esc_storage::size() const {
    return this->data.size();
}


const esc_storage::value esc_storage::row::get(const column column, const value default_value) const{
    row_map::const_iterator iterator = this->data.find(column);
    if (iterator == this->data.end()) {
        return value("");
    } else {
        return iterator->second;
    }
};

bool esc_storage::row::is_empty() const {
    return this->data.empty();
};

esc_storage::row::row_map::const_iterator esc_storage::row::begin() const {
    return this->data.begin();
}

esc_storage::row::row_map::const_iterator esc_storage::row::end() const {
    return this->data.end();
}
