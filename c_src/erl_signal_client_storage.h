#pragma once

#include <string.h>
#include <iostream>
#include <list>
#include <map>



#include "cJSON/cJSON.h"

class esc_storage {
    public:        

        typedef std::string column;
        typedef std::string value;    

        class row {
            public:
                typedef std::map <column, value> row_map;
            private:
                row_map data;
            public:                
                bool is_empty() const;
                void store(const column column, const value value);
                const value get(const column column, const value default_value) const;
                row_map::const_iterator begin() const;
                row_map::const_iterator end() const;
        };

        typedef std::string key;
        typedef std::map <key, row> storage;     
    
    private:
        storage data;
    protected:
        bool is_changed = false;                
    public:
        esc_storage();
        ~esc_storage();
        void set(const key key, const row row );
        const row get(const key key) const;
        bool is_member(const key key) const;
        void erase(const key key);
        storage::const_iterator begin() const;
        storage::const_iterator end() const;        
        void flush();
        std::list <row> get_nearby(const key key) const; 
        int erase_nearby(const key key);
        void clear();
        std::list <key> keys() const;
        int size() const;
        //std::string serialize();
        //int unserialize(const std::string str);
};
