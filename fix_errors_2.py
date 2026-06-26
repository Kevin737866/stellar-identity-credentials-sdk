import re

def replace_in_file(filename, search, replace):
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    content = content.replace(search, replace)
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)

def fix_all():
    # did_recovery.rs
    with open('src/did_recovery.rs', 'r', encoding='utf-8') as f:
        content = f.read()
    content = content.replace("env.clone(), controller, did.clone(), guardian.clone()", "env.clone(), controller.clone(), did.clone(), guardian.clone()")
    content = content.replace("            controller,\n", "            controller.clone(),\n")
    content = content.replace("            new_controller,\n", "            new_controller.clone(),\n")
    content = content.replace("execute_recovery(env.clone(), controller, request_id)", "execute_recovery(env.clone(), controller.clone(), request_id)")
    content = content.replace("deactivate_recovery(env.clone(), controller, did.clone())", "deactivate_recovery(env.clone(), controller.clone(), did.clone())")
    content = content.replace("initiate_recovery(env.clone(), ttp, did.clone(), new_controller, None)", "initiate_recovery(env.clone(), ttp.clone(), did.clone(), new_controller.clone(), None)")
    with open('src/did_recovery.rs', 'w', encoding='utf-8') as f:
        f.write(content)

    # did_registry.rs
    with open('src/did_registry.rs', 'r', encoding='utf-8') as f:
        content = f.read()
    content = content.replace("let addr = Address::generate(&env);", "let _addr = Address::generate(&env);")
    with open('src/did_registry.rs', 'w', encoding='utf-8') as f:
        f.write(content)

    # integration_tests.rs
    replace_in_file('src/integration_tests.rs', 'env.register_contract(None, ZKAttestationContract)', 'env.register(ZKAttestationContract, ())')
    # wait, the deprecation is `env.register(...)` taking two arguments, or `env.register_contract`? 
    # Ah, Soroban SDK changed `env.register_contract(None, Contract)` to `env.register(Contract, ())` or similar. Let's just use `register(Contract, ())`
    
    # schema_registry.rs
    with open('src/schema_registry.rs', 'r', encoding='utf-8') as f:
        content = f.read()
    content = content.replace("use soroban_sdk::{contract, contracterror, contractimpl, Address, Bytes, Env, Symbol, Vec};", "use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Symbol};")
    with open('src/schema_registry.rs', 'w', encoding='utf-8') as f:
        f.write(content)

    # zk_attestation.rs
    with open('src/zk_attestation.rs', 'r', encoding='utf-8') as f:
        content = f.read()
    content = content.replace("contracttype, symbol_short, Address", "contracttype, Address")
    with open('src/zk_attestation.rs', 'w', encoding='utf-8') as f:
        f.write(content)

    # credential_offer.rs
    with open('src/credential_offer.rs', 'r', encoding='utf-8') as f:
        content = f.read()
    content = content.replace("holderOffers(holder)", "holderOffers(holder.clone())")
    content = content.replace("IssuerOffers(issuer)", "IssuerOffers(issuer.clone())")
    content = content.replace("(offer_id.clone(), issuer, holder),", "(offer_id.clone(), issuer.clone(), holder.clone()),")
    with open('src/credential_offer.rs', 'w', encoding='utf-8') as f:
        f.write(content)

fix_all()
