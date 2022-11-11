__kernel void compare(__global uint *packet, __global uint *rule, __global bool *result){
       /* n rule 10 local group */

       __local uint local_input1;
       __local bool local_output;

       int global_id = get_global_id(0);
       local_input1 = packet[global_id];

       local_output = local_input1 == rule[global_id];

       result[global_id] = local_output;
}
    /*result[0] = packet[0] == (rule[0]&&mask);*/