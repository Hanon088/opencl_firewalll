__kernel void compare(__global uint *packet, __global uint *rule, __global uint *mask, __global bool *result){
       /* n rule 10 local group */

       __local uint local_input1;
       __local uint local_rule;
       __local uint local_mask;
       __local bool local_output;

       int packet_global_id_0 = get_global_id(0);
       int packet_global_id_1 = get_global_id(1);
       int packet_index = packet_global_id_1 * get_global_size(0) + packet_global_id_0;

       local_input1 = packet[get_global_id(1)];
       local_rule = rule[get_global_id(0)];
       local_mask = mask[get_global_id(0)];
       local_output = local_rule == (local_input1 & local_mask);


       result[packet_index] = local_output;
}
    /*result[0] = packet[0] == (rule[0]&&mask);*/