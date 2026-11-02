#include <stdio.h>
#include <string.h>
#include "dicom.h"
#include "../../llm/dicom/dicom_fixers.c"

static int test_header(void){
    dicom_packet_t p; memset(&p,0,sizeof(p));
    p.type=DICOM_PKT_P_DATA_TF; p.raw_length=12; p.raw_data[0]=0xff; p.raw_data[1]=0xff;
    fix_dicom_pdu_header_lengths(&p,1);
    return p.raw_data[0]==DICOM_PDU_P_DATA_TF && p.raw_data[1]==0 && p.raw_data[5]==6;
}
static int test_assoc(void){
    dicom_packet_t p; memset(&p,0,sizeof(p));
    p.type=DICOM_PKT_A_ASSOCIATE_RQ; p.raw_length=80; memset(p.raw_data,0xff,p.raw_length);
    fix_associate_rq_constraints(&p,1);
    return p.u.a_associate_rq.protocol_version==1 && p.raw_data[6]==0 && p.raw_data[7]==1 && p.raw_data[42]==0;
}
static int test_pdata(void){
    dicom_packet_t p; memset(&p,0,sizeof(p));
    p.type=DICOM_PKT_P_DATA_TF; p.raw_length=14; p.raw_data[0]=4; p.raw_data[1]=0; p.raw_data[2]=0; p.raw_data[3]=0; p.raw_data[4]=0; p.raw_data[5]=8;
    p.raw_data[6]=0; p.raw_data[7]=0; p.raw_data[8]=0; p.raw_data[9]=4; p.raw_data[10]=2; p.raw_data[11]=0xff; p.raw_data[12]=1; p.raw_data[13]=2;
    fix_p_data_tf_constraints(&p,1);
    return p.raw_data[10]==3 && (p.raw_data[11]&~0x03)==0;
}
static int test_release_abort(void){
    dicom_packet_t p[2]; memset(p,0,sizeof(p));
    p[0].type=DICOM_PKT_A_RELEASE_RQ; p[0].raw_length=20; memset(p[0].raw_data,0xff,20);
    p[1].type=DICOM_PKT_A_ABORT; p[1].raw_length=20; memset(p[1].raw_data,0xff,20);
    fix_release_abort_constraints(p,2);
    return p[0].raw_length==10 && p[0].raw_data[0]==DICOM_PDU_A_RELEASE_RQ && p[1].raw_length==10 && p[1].raw_data[0]==DICOM_PDU_A_ABORT;
}
int main(void){
    int passed=0, failed=0;
    if(test_header()){puts("[PASS] fix_dicom_pdu_header_lengths");passed++;}else{puts("[FAIL] fix_dicom_pdu_header_lengths");failed++;}
    if(test_assoc()){puts("[PASS] fix_associate_rq_constraints");passed++;}else{puts("[FAIL] fix_associate_rq_constraints");failed++;}
    if(test_pdata()){puts("[PASS] fix_p_data_tf_constraints");passed++;}else{puts("[FAIL] fix_p_data_tf_constraints");failed++;}
    if(test_release_abort()){puts("[PASS] fix_release_abort_constraints");passed++;}else{puts("[FAIL] fix_release_abort_constraints");failed++;}
    printf("%s passed=%d failed=%d total=%d\n", failed?"[FAIL]":"[PASS]", passed, failed, passed+failed);
    return failed?1:0;
}
