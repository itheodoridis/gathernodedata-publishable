ttp_template = """
<group name="ip-arps*">
mac-address: {{ mac_address }},ip-address: {{ host_ip }},interface: {{ port }},switch: {{ switch_name }},switch-ip-address: {{ switch_ip }},switch-location: {{ switch_location }}
</group>
"""