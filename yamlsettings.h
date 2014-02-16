
int MergeSpecData(desc_settings *out, desc_settings *desc, rsf_settings *rsf);
void EvaluateRSF(rsf_settings *rsf, ctr_yaml_context *ctx);
void EvaluateDESC(desc_settings *desc, ctr_yaml_context *ctx);

void GET_Option(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_AccessControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_SystemControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_BasicInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_Rom(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_ExeFs(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_PlainRegion(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_TitleInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_CardInfo(ctr_yaml_context *ctx, rsf_settings *rsf);

void GET_AccessControlDescriptor(ctr_yaml_context *ctx, desc_settings *desc);
void GET_CommonHeaderKey(ctr_yaml_context *ctx, desc_settings *desc);