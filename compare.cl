__kernel void compare(__global ulong *input_ip,
                      __global ushort *input_sport,
                      __global ushort *input_dport,
                      __global uchar *input_protocol,
                      __global ulong *rule_ip,
                      __global ulong *rule_mask,
                      __global ushort *rule_sport,
                      __global ushort *rule_dport,
                      __global uchar *rule_protocol,
                      __global int *result){
       /* n rule n packet */

       __local ulong local_input_ip;
       __local ushort local_input_sport;
       __local ushort local_input_dport;
       __local uchar local_input_protocol;

       __local ulong local_rule_ip;
       __local ulong local_rule_mask;
       __local ushort local_rule_sport;
       __local ushort local_rule_dport;
       __local uchar local_rule_protocol;

       __local int local_output;

       int rule_index  = get_global_id(0);
       int input_index  = get_global_id(1);

       local_input_ip = input_ip[input_index];
       local_input_sport = input_sport[input_index];
       local_input_dport = input_dport[input_index];
       local_input_protocol = input_protocol[input_index];

       local_rule_ip = rule_ip[rule_index];
       local_rule_mask = rule_mask[rule_index];
       local_rule_sport = rule_sport[rule_index];
       local_rule_dport = rule_dport[rule_index];
       local_rule_protocol = rule_protocol[rule_index];

       int packet_global_id_0 = get_global_id(0);
       int packet_global_id_1 = get_global_id(1);
       int packet_index = packet_global_id_1 * get_global_size(0) + packet_global_id_0;

       if(local_rule_protocol == 0){local_input_protocol = 0;}
       if(local_rule_sport == 0){local_input_sport = 0;}
       if(local_rule_dport == 0){local_input_dport = 0;}

       local_output = ((local_input_ip & local_rule_mask) == local_rule_ip)
        & (local_rule_protocol == local_input_protocol) & (local_rule_sport == local_input_sport)
         & (local_rule_dport == local_input_dport);
       result[packet_index] = local_output;

}

__kernel void sync_rule_and_verdict(__global int *set_already_compare, __global int *verdict,
    __global int *result ,__global int *rule_size){

    __local int local_result;
    __local int input1;
    local_result = 0;
    int global_id = get_global_id(0) * rule_size[0];
    for (int i = 0; i < rule_size[0]; i++){
        input1 = set_already_compare[global_id+i];
        if (input1 == 1){
            local_result = verdict[i];
            i = rule_size[0];
        }
    }
    result[get_global_id(0)] = local_result;
}
