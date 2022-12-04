__kernel void compare(__global uint *packet, __global uint *rule,
                      __global uint *mask, __global bool *result) {
  /* n rule n packet */

  __local uint local_input1;
  __local uint local_rule;
  __local uint local_mask;
  __local bool local_output;

  int packet_global_id_0 = get_global_id(0);
  int packet_global_id_1 = get_global_id(1);
  int packet_index =
      packet_global_id_1 * get_global_size(0) + packet_global_id_0;

  local_input1 = packet[get_global_id(1)];
  local_rule = rule[get_global_id(0)];
  local_mask = mask[get_global_id(0)];
  local_output = local_rule == (local_input1 & local_mask);

  result[packet_index] = local_output;
}

__kernel void sync_rule_and_verdict(__global bool *set_already_compare,
                                    __global int *verdict, __global int *result,
                                    __global int *rule_size) {

  __local int local_result;
  __local bool input1, input2, input3, input4;
  local_result = 0;
  int global_id = get_global_id(0) * rule_size[0];
  for (int i = 0; i < rule_size[0]; i++) {
    input1 = set_already_compare[global_id + i];
    if (input1) {
      local_result = verdict[i];
      i = rule_size[0];
    }
  }
  result[get_global_id(0)] = local_result;
}
/*result[0] = packet[0] == (rule[0]&&mask);*/