
/* Auto-generated by the GenerateIDMEFTreeData package */

typedef struct {
	char *name;
	int list;
	idmef_value_type_id_t type;
	idmef_object_type_t object_type;
} children_list_t;

const children_list_t idmef_additional_data_children_list[] = {
        { "type", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_ADDITIONAL_DATA_TYPE },
        { "meaning", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "data", 0, IDMEF_VALUE_TYPE_DATA, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_reference_children_list[] = {
        { "origin", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_REFERENCE_ORIGIN },
        { "name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "url", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "meaning", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_classification_children_list[] = {
        { "ident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "text", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "reference", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_REFERENCE },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_user_id_children_list[] = {
        { "ident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "type", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_USER_ID_TYPE },
        { "tty", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "number", 0, IDMEF_VALUE_TYPE_UINT32, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_user_children_list[] = {
        { "ident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "category", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_USER_CATEGORY },
        { "user_id", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_USER_ID },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_address_children_list[] = {
        { "ident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "category", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_ADDRESS_CATEGORY },
        { "vlan_name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "vlan_num", 0, IDMEF_VALUE_TYPE_INT32, 0 },
        { "address", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "netmask", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_process_children_list[] = {
        { "ident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "pid", 0, IDMEF_VALUE_TYPE_UINT32, 0 },
        { "path", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "arg", 1, IDMEF_VALUE_TYPE_STRING, 0 },
        { "env", 1, IDMEF_VALUE_TYPE_STRING, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_web_service_children_list[] = {
        { "url", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "cgi", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "http_method", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "arg", 1, IDMEF_VALUE_TYPE_STRING, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_snmp_service_children_list[] = {
        { "oid", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "community", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "security_name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "context_name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "context_engine_id", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "command", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_service_children_list[] = {
        { "ident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "ip_version", 0, IDMEF_VALUE_TYPE_UINT8, 0 },
        { "iana_protocol_number", 0, IDMEF_VALUE_TYPE_UINT8, 0 },
        { "iana_protocol_name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "port", 0, IDMEF_VALUE_TYPE_UINT16, 0 },
        { "portlist", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "protocol", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "type", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_SERVICE_TYPE },
        { "web_service", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_WEB_SERVICE },
        { "snmp_service", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_SNMP_SERVICE },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_node_children_list[] = {
        { "ident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "category", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_NODE_CATEGORY },
        { "location", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "address", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_ADDRESS },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_source_children_list[] = {
        { "ident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "spoofed", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_SOURCE_SPOOFED },
        { "interface", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "node", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_NODE },
        { "user", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_USER },
        { "process", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_PROCESS },
        { "service", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_SERVICE },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_file_access_children_list[] = {
        { "user_id", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_USER_ID },
        { "permission", 1, IDMEF_VALUE_TYPE_STRING, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_inode_children_list[] = {
        { "change_time", 0, IDMEF_VALUE_TYPE_TIME, 0 },
        { "number", 0, IDMEF_VALUE_TYPE_UINT32, 0 },
        { "major_device", 0, IDMEF_VALUE_TYPE_UINT32, 0 },
        { "minor_device", 0, IDMEF_VALUE_TYPE_UINT32, 0 },
        { "c_major_device", 0, IDMEF_VALUE_TYPE_UINT32, 0 },
        { "c_minor_device", 0, IDMEF_VALUE_TYPE_UINT32, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_checksum_children_list[] = {
        { "value", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "key", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "algorithm", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_CHECKSUM_ALGORITHM },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_file_children_list[] = {
        { "ident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "path", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "create_time", 0, IDMEF_VALUE_TYPE_TIME, 0 },
        { "modify_time", 0, IDMEF_VALUE_TYPE_TIME, 0 },
        { "access_time", 0, IDMEF_VALUE_TYPE_TIME, 0 },
        { "data_size", 0, IDMEF_VALUE_TYPE_UINT64, 0 },
        { "disk_size", 0, IDMEF_VALUE_TYPE_UINT64, 0 },
        { "file_access", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_FILE_ACCESS },
        { "linkage", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_LINKAGE },
        { "inode", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_INODE },
        { "checksum", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_CHECKSUM },
        { "category", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_FILE_CATEGORY },
        { "fstype", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_FILE_FSTYPE },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_linkage_children_list[] = {
        { "category", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_LINKAGE_CATEGORY },
        { "name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "path", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "file", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_FILE },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_target_children_list[] = {
        { "ident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "decoy", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_TARGET_DECOY },
        { "interface", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "node", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_NODE },
        { "user", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_USER },
        { "process", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_PROCESS },
        { "service", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_SERVICE },
        { "file", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_FILE },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_analyzer_children_list[] = {
        { "analyzerid", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "manufacturer", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "model", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "version", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "class", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "ostype", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "osversion", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "node", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_NODE },
        { "process", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_PROCESS },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_alertident_children_list[] = {
        { "alertident", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "analyzerid", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_impact_children_list[] = {
        { "severity", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_IMPACT_SEVERITY },
        { "completion", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_IMPACT_COMPLETION },
        { "type", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_IMPACT_TYPE },
        { "description", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_action_children_list[] = {
        { "category", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_ACTION_CATEGORY },
        { "description", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_confidence_children_list[] = {
        { "rating", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_CONFIDENCE_RATING },
        { "confidence", 0, IDMEF_VALUE_TYPE_FLOAT, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_assessment_children_list[] = {
        { "impact", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_IMPACT },
        { "action", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_ACTION },
        { "confidence", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_CONFIDENCE },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_tool_alert_children_list[] = {
        { "name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "command", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "alertident", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_ALERTIDENT },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_correlation_alert_children_list[] = {
        { "name", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "alertident", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_ALERTIDENT },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_overflow_alert_children_list[] = {
        { "program", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "size", 0, IDMEF_VALUE_TYPE_UINT32, 0 },
        { "buffer", 0, IDMEF_VALUE_TYPE_DATA, 0 },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_alert_children_list[] = {
        { "messageid", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "analyzer", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_ANALYZER },
        { "create_time", 0, IDMEF_VALUE_TYPE_TIME, 0 },
        { "classification", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_CLASSIFICATION },
        { "detect_time", 0, IDMEF_VALUE_TYPE_TIME, 0 },
        { "analyzer_time", 0, IDMEF_VALUE_TYPE_TIME, 0 },
        { "source", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_SOURCE },
        { "target", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_TARGET },
        { "assessment", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_ASSESSMENT },
        { "additional_data", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_ADDITIONAL_DATA },
        { "type", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_ALERT_TYPE },
        { "tool_alert", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_TOOL_ALERT },
        { "correlation_alert", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_CORRELATION_ALERT },
        { "overflow_alert", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_OVERFLOW_ALERT },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_heartbeat_children_list[] = {
        { "messageid", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "analyzer", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_ANALYZER },
        { "create_time", 0, IDMEF_VALUE_TYPE_TIME, 0 },
        { "analyzer_time", 0, IDMEF_VALUE_TYPE_TIME, 0 },
        { "heartbeat_interval", 0, IDMEF_VALUE_TYPE_UINT32, 0 },
        { "additional_data", 1, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_ADDITIONAL_DATA },
        { NULL, 0, 0, 0 }
};

const children_list_t idmef_message_children_list[] = {
        { "version", 0, IDMEF_VALUE_TYPE_STRING, 0 },
        { "type", 0, IDMEF_VALUE_TYPE_ENUM, IDMEF_OBJECT_TYPE_MESSAGE_TYPE },
        { "alert", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_ALERT },
        { "heartbeat", 0, IDMEF_VALUE_TYPE_OBJECT, IDMEF_OBJECT_TYPE_HEARTBEAT },
        { NULL, 0, 0, 0 }
};


typedef struct {
	char *name;
	const children_list_t *children_list;
	int (*get_child)(void *ptr, idmef_child_t child, void **ret);
	int (*new_child)(void *ptr, idmef_child_t child, int n, void **ret);
	int (*to_numeric)(const char *name);
	const char *(*to_string)(int val);
} object_data_t;


const object_data_t object_data[] = {
        { "(unassigned)", NULL, NULL, NULL }, /* ID: 0 */
        { "(unassigned)", NULL, NULL, NULL }, /* ID: 1 */
        { "(unassigned)", NULL, NULL, NULL }, /* ID: 2 */
        { "additional_data_type", NULL, NULL, NULL, idmef_additional_data_type_to_numeric, idmef_additional_data_type_to_string}, /* ID: 3 */
        { "additional_data", idmef_additional_data_children_list, idmef_additional_data_get_child, idmef_additional_data_new_child, NULL, NULL }, /* ID: 4 */
        { "reference_origin", NULL, NULL, NULL, idmef_reference_origin_to_numeric, idmef_reference_origin_to_string}, /* ID: 5 */
        { "classification", idmef_classification_children_list, idmef_classification_get_child, idmef_classification_new_child, NULL, NULL }, /* ID: 6 */
        { "user_id_type", NULL, NULL, NULL, idmef_user_id_type_to_numeric, idmef_user_id_type_to_string}, /* ID: 7 */
        { "user_id", idmef_user_id_children_list, idmef_user_id_get_child, idmef_user_id_new_child, NULL, NULL }, /* ID: 8 */
        { "user_category", NULL, NULL, NULL, idmef_user_category_to_numeric, idmef_user_category_to_string}, /* ID: 9 */
        { "user", idmef_user_children_list, idmef_user_get_child, idmef_user_new_child, NULL, NULL }, /* ID: 10 */
        { "address_category", NULL, NULL, NULL, idmef_address_category_to_numeric, idmef_address_category_to_string}, /* ID: 11 */
        { "address", idmef_address_children_list, idmef_address_get_child, idmef_address_new_child, NULL, NULL }, /* ID: 12 */
        { "process", idmef_process_children_list, idmef_process_get_child, idmef_process_new_child, NULL, NULL }, /* ID: 13 */
        { "web_service", idmef_web_service_children_list, idmef_web_service_get_child, idmef_web_service_new_child, NULL, NULL }, /* ID: 14 */
        { "snmp_service", idmef_snmp_service_children_list, idmef_snmp_service_get_child, idmef_snmp_service_new_child, NULL, NULL }, /* ID: 15 */
        { "service_type", NULL, NULL, NULL, idmef_service_type_to_numeric, idmef_service_type_to_string}, /* ID: 16 */
        { "service", idmef_service_children_list, idmef_service_get_child, idmef_service_new_child, NULL, NULL }, /* ID: 17 */
        { "node_category", NULL, NULL, NULL, idmef_node_category_to_numeric, idmef_node_category_to_string}, /* ID: 18 */
        { "node", idmef_node_children_list, idmef_node_get_child, idmef_node_new_child, NULL, NULL }, /* ID: 19 */
        { "source_spoofed", NULL, NULL, NULL, idmef_source_spoofed_to_numeric, idmef_source_spoofed_to_string}, /* ID: 20 */
        { "source", idmef_source_children_list, idmef_source_get_child, idmef_source_new_child, NULL, NULL }, /* ID: 21 */
        { "file_access", idmef_file_access_children_list, idmef_file_access_get_child, idmef_file_access_new_child, NULL, NULL }, /* ID: 22 */
        { "inode", idmef_inode_children_list, idmef_inode_get_child, idmef_inode_new_child, NULL, NULL }, /* ID: 23 */
        { "file_category", NULL, NULL, NULL, idmef_file_category_to_numeric, idmef_file_category_to_string}, /* ID: 24 */
        { "file_fstype", NULL, NULL, NULL, idmef_file_fstype_to_numeric, idmef_file_fstype_to_string}, /* ID: 25 */
        { "file", idmef_file_children_list, idmef_file_get_child, idmef_file_new_child, NULL, NULL }, /* ID: 26 */
        { "linkage_category", NULL, NULL, NULL, idmef_linkage_category_to_numeric, idmef_linkage_category_to_string}, /* ID: 27 */
        { "linkage", idmef_linkage_children_list, idmef_linkage_get_child, idmef_linkage_new_child, NULL, NULL }, /* ID: 28 */
        { "target_decoy", NULL, NULL, NULL, idmef_target_decoy_to_numeric, idmef_target_decoy_to_string}, /* ID: 29 */
        { "target", idmef_target_children_list, idmef_target_get_child, idmef_target_new_child, NULL, NULL }, /* ID: 30 */
        { "analyzer", idmef_analyzer_children_list, idmef_analyzer_get_child, idmef_analyzer_new_child, NULL, NULL }, /* ID: 31 */
        { "alertident", idmef_alertident_children_list, idmef_alertident_get_child, idmef_alertident_new_child, NULL, NULL }, /* ID: 32 */
        { "impact_severity", NULL, NULL, NULL, idmef_impact_severity_to_numeric, idmef_impact_severity_to_string}, /* ID: 33 */
        { "impact_completion", NULL, NULL, NULL, idmef_impact_completion_to_numeric, idmef_impact_completion_to_string}, /* ID: 34 */
        { "impact_type", NULL, NULL, NULL, idmef_impact_type_to_numeric, idmef_impact_type_to_string}, /* ID: 35 */
        { "impact", idmef_impact_children_list, idmef_impact_get_child, idmef_impact_new_child, NULL, NULL }, /* ID: 36 */
        { "action_category", NULL, NULL, NULL, idmef_action_category_to_numeric, idmef_action_category_to_string}, /* ID: 37 */
        { "action", idmef_action_children_list, idmef_action_get_child, idmef_action_new_child, NULL, NULL }, /* ID: 38 */
        { "confidence_rating", NULL, NULL, NULL, idmef_confidence_rating_to_numeric, idmef_confidence_rating_to_string}, /* ID: 39 */
        { "confidence", idmef_confidence_children_list, idmef_confidence_get_child, idmef_confidence_new_child, NULL, NULL }, /* ID: 40 */
        { "assessment", idmef_assessment_children_list, idmef_assessment_get_child, idmef_assessment_new_child, NULL, NULL }, /* ID: 41 */
        { "tool_alert", idmef_tool_alert_children_list, idmef_tool_alert_get_child, idmef_tool_alert_new_child, NULL, NULL }, /* ID: 42 */
        { "correlation_alert", idmef_correlation_alert_children_list, idmef_correlation_alert_get_child, idmef_correlation_alert_new_child, NULL, NULL }, /* ID: 43 */
        { "overflow_alert", idmef_overflow_alert_children_list, idmef_overflow_alert_get_child, idmef_overflow_alert_new_child, NULL, NULL }, /* ID: 44 */
        { "alert_type", NULL, NULL, NULL, idmef_alert_type_to_numeric, idmef_alert_type_to_string}, /* ID: 45 */
        { "alert", idmef_alert_children_list, idmef_alert_get_child, idmef_alert_new_child, NULL, NULL }, /* ID: 46 */
        { "heartbeat", idmef_heartbeat_children_list, idmef_heartbeat_get_child, idmef_heartbeat_new_child, NULL, NULL }, /* ID: 47 */
        { "message_type", NULL, NULL, NULL, idmef_message_type_to_numeric, idmef_message_type_to_string}, /* ID: 48 */
        { "message", idmef_message_children_list, idmef_message_get_child, idmef_message_new_child, NULL, NULL }, /* ID: 49 */
        { "reference", idmef_reference_children_list, idmef_reference_get_child, idmef_reference_new_child, NULL, NULL }, /* ID: 50 */
        { "(unassigned)", NULL, NULL, NULL }, /* ID: 51 */
        { "checksum", idmef_checksum_children_list, idmef_checksum_get_child, idmef_checksum_new_child, NULL, NULL }, /* ID: 52 */
        { "checksum_algorithm", NULL, NULL, NULL, idmef_checksum_algorithm_to_numeric, idmef_checksum_algorithm_to_string}, /* ID: 53 */
        { NULL, NULL, NULL, NULL }
};
