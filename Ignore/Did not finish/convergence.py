import pandas as pd 

TIME = 10
BANDWIDTH = 10

flows = pd.read_excel('sample_flows.xlsx')
print(flows)

current_time = 0
last_flow = 0
bandwidth_used = 0

while current_time <= TIME:
    if(flows.loc[last_flow]['Time of Entry'] == current_time):



    current_time = current_time + 1


# check if any flows have finished - alleviate bandwidth
# check if any new flows have entered - allocate bandwidth
    # while not all flows have been allocated
        # if necessary bandwidth is unavailable, calculate an even distribution
            # for each flow that does not need their full distribution, give them what they need
            # otherwise, allocate 
