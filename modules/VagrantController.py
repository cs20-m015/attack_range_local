
from jinja2 import Environment, FileSystemLoader
import vagrant
from tabulate import tabulate
import re
import ansible_runner
import sys
import os
import yaml
import json
from modules import splunk_sdk


class VagrantController():


    def __init__(self, config, log):
        self.config = config
        self.log = log

        if self.config['install_es'] == '1':
            self.config['splunk_es_app_version'] = re.findall(r'\d+', self.config['splunk_es_app'])[0]

        self.vagrantfile = 'Vagrant.configure("2") do |config| \n \n'

        if config['phantom_server'] == '1':
            self.vagrantfile += self.read_vagrant_file('phantom-server/Vagrantfile')
            self.vagrantfile += '\n\n'
        if config['splunk_server'] == '1':
            self.vagrantfile += self.read_vagrant_file('splunk_server/Vagrantfile')
            self.vagrantfile += '\n\n'
        # if config['splunk_server'] == '0':
        #     self.vagrantfile += self.read_vagrant_file('caldera-server/Vagrantfile')
        #     self.vagrantfile += '\n\n'
        if config['windows_domain_controller'] == '1':
            self.vagrantfile += self.read_vagrant_file('windows-domain-controller/Vagrantfile')
            self.vagrantfile += '\n\n'
        if config['windows_client'] == '1':
            self.vagrantfile += self.read_vagrant_file('windows10/Vagrantfile')
            self.vagrantfile += '\n\n'
        if config['windows_server'] == '1':
            self.vagrantfile += self.read_vagrant_file('windows-server/Vagrantfile')
            self.vagrantfile += '\n\n'
        if config['kali_machine'] == '1':
            self.vagrantfile += self.read_vagrant_file('kali-machine/Vagrantfile')
            self.vagrantfile += '\n\n'
        self.vagrantfile += '\nend'
        with open('vagrant/Vagrantfile', 'w') as file:
            file.write(self.vagrantfile)


    def read_vagrant_file(self, path):
        j2_env = Environment(loader=FileSystemLoader('vagrant'),trim_blocks=True)
        template = j2_env.get_template(path)
        vagrant_file = template.render(self.config)
        return vagrant_file


    def build(self):
        self.log.info("[action] > build\n")
        v1 = vagrant.Vagrant('vagrant/', quiet_stdout=False, quiet_stderr=False)
        try:
            v1.up(provision=True, provider="virtualbox")
        except:
            self.log.error("vagrant failed to build")
            sys.exit(1)

        self.log.info("attack_range has been built using vagrant successfully")
        self.list_machines()


    def destroy(self):
        self.log.info("[action] > destroy\n")
        v1 = vagrant.Vagrant('vagrant/', quiet_stdout=False)
        v1.destroy()
        self.log.info("attack_range has been destroy using vagrant successfully")


    def stop(self, target=""):
        print("[action] > stop\n")
        v1 = vagrant.Vagrant('vagrant/', quiet_stdout=False)
        if target == "":
            v1.halt()
        else:
            v1.halt(vm_name=target)


    def resume(self, target=""):
        print("[action] > resume\n")
        v1 = vagrant.Vagrant('vagrant/', quiet_stdout=False)
        if target == "":
            v1.up()
        else:
            v1.up(vm_name=target)


    def simulate(self, target, simulation_techniques, simulation_atomics):

        # check if specific atomics are used then it's not allowed to multiple techniques
        techniques_arr = simulation_techniques.split(',')
        if (len(techniques_arr) > 1) and (simulation_atomics != 'no'):
            self.log.error('ERROR: if simulation_atomics are used, only a single simulation_technique is allowed.')
            sys.exit(1)

        run_specific_atomic_tests = 'True'
        if simulation_atomics == 'no':
            run_specific_atomic_tests = 'False'

        # get ip address from machine
        self.check_targets_running_vagrant(target, self.log)
        target_ip = self.get_ip_address_from_machine(target)
        runner = ansible_runner.run(private_data_dir='.',
                               cmdline=str('-i ' + target_ip + ', '),
                               roles_path="ansible/roles",
                               playbook='ansible/atomic_red_team.yml',
                               extravars={'art_branch': self.config['art_branch'], 'art_repository': self.config['art_repository'], 'run_specific_atomic_tests': run_specific_atomic_tests, 'art_run_tests': simulation_atomics, 'art_run_techniques': simulation_techniques, 'ansible_user': 'Vagrant', 'ansible_password': 'vagrant', 'ansible_port': 5985, 'ansible_winrm_scheme': 'http'},
                               verbosity=0)

        if runner.status == "successful":
            self.log.info("successfully executed technique ID {0} against target: {1}".format(simulation_techniques, target))
        else:
            self.log.error("failed to executed technique ID {0} against target: {1}".format(simulation_techniques, target))
            sys.exit(1)


    def get_ip_address_from_machine(self, box):
        pattern = 'config.vm.define "' + box + '"[\s\S]*?:private_network, ip: "([^"]+)'
        match = re.search(pattern, self.vagrantfile)
        return match.group(1)


    def check_targets_running_vagrant(self, target, log):
        v1 = vagrant.Vagrant('vagrant/', quiet_stdout=False)
        status = v1.status()

        found_box = False
        for stat in status:
            if stat.name == target:
                found_box = True
                if not (stat.state == 'running'):
                    log.error(target + ' not running.')
                    sys.exit(1)
                break
        if not found_box:
            log.error(target + ' not found as vagrant box.')
            sys.exit(1)


    def list_machines(self):
        print()
        print('Vagrant Status\n')
        v1 = vagrant.Vagrant('vagrant/', quiet_stdout=False)
        response = v1.status()
        status = []
        for stat in response:
            status.append([stat.name, stat.state, self.get_ip_address_from_machine(stat.name)])

        print(tabulate(status, headers=['Name','Status','IP Address']))
        print()

    def dump(self, dump_name):
        self.log.info("Dump log data")

        folder = "attack_data/" + dump_name
        os.mkdir(os.path.join(os.path.dirname(__file__), '../' + folder))


        with open(os.path.join(os.path.dirname(__file__), '../attack_data/dumps.yml')) as dumps:
            for dump in yaml.full_load(dumps):
                if dump['enabled']:
                    dump_out = dump['dump_parameters']['out']
                    dump_search = "search %s earliest=%s | sort 0 _time" \
                                  % (dump['dump_parameters']['search'], dump['dump_parameters']['time'])
                    dump_info = "Dumping Splunk Search to %s " % dump_out
                    self.log.info(dump_info)
                    out = open(os.path.join(os.path.dirname(__file__), "../attack_data/" + dump_name + "/" + dump_out), 'wb')
                    splunk_sdk.export_search(self.config['splunk_server_private_ip'],
                                             s=dump_search,
                                             password=self.config['splunk_admin_password'],
                                             out=out)
                    out.close()
                    self.log.info("%s [Completed]" % dump_info)

    
    def test(self, test_files, output_file, test_delete_data=False):
        detected=[]
        result_tests = []
        for test_file in test_files:
            self.log.info("running test: {0}".format(test_file))
            test_file = self.load_file(test_file)

            for test in test_file['tests']:
                result_test = {}

                # process baselines
                if 'baselines' in test:
                    results_baselines = []
                    for baseline_obj in test['baselines']:
                        baseline_file_name = baseline_obj['file']
                        baseline = self.load_file(os.path.join(os.path.dirname(__file__), '../' + self.config['security_content_path'] + '/' + baseline_file_name))
                        result_obj = dict()
                        result_obj['baseline'] = baseline_obj['name']
                        result_obj['baseline_file'] = baseline_obj['file']
                        result = self.get_baseline_result(baseline_obj, baseline)
                        if result:
                            results_baselines.append(result)
                    result_test['baselines_result'] = results_baselines

                # validate detection works
                detection_file_name = test['file']
                detection = self.load_file(os.path.join(os.path.dirname(__file__), '../' + self.config['security_content_path'] + '/detections/' + detection_file_name))
                result_detection = self.get_detection_result(detection, test, test_delete_data)

                result_detection['detection_name'] = test['name']
                result_detection['detection_file'] = test['file']
                result_test['detection_result'] = result_detection
                result_tests.append(result_test)
                try:
                    if int(result_detection['resultCount']) > 0:
                        detected.append(result_detection['detection_name'])
                except KeyError as e:
                    print(e)
                    continue

        self.log.info('testing completed.')
        print("########################################")
        print(f"Results - {len(detected)} found:")
        if len(detected) == 0:
            print("Nothing detected.")
        for detection in detected:
            print(detection)

        if output_file != "":
            self.log.info(f'dumping results to {output_file}')
            data = json.dumps(result_tests)
            with open(os.path.join(os.path.dirname(__file__), f'../{output_file}.json'), 'w+') as f:
                f.write(data)   
            self.log.info(f'completed')
        return

    def get_baseline_result(self, baseline_obj, baseline):

        result = {}
        instance_ip, splunk_rest_port = self.get_instance_ip_and_port()

        if instance_ip and splunk_rest_port:
            result = splunk_sdk.test_baseline_search(instance_ip, str(self.config['splunk_admin_password']),
                                                     baseline['search'], baseline_obj['pass_condition'],
                                                     baseline['name'], baseline_obj['file'],
                                                     baseline_obj['earliest_time'], baseline_obj['latest_time'],
                                                     self.log, splunk_rest_port)
            
        return result
                                                     

    def get_detection_result(self, detection, test, test_delete_data):

        result = {}
        instance_ip, splunk_rest_port = self.get_instance_ip_and_port()

        if instance_ip and splunk_rest_port:
            self.log.info("running detection against splunk for indexed data {0}".format(test['file']))
            result = splunk_sdk.test_detection_search(instance_ip, str(self.config['splunk_admin_password']),
                                                      detection['search'], test['pass_condition'],
                                                      detection['name'], test['file'],
                                                      test['earliest_time'], test['latest_time'], self.log, splunk_rest_port)

            if test_delete_data:
                indexes = set()
                for attack_data in test.get('attack_data'):
                    indexes.add(attack_data.get('custom_index', 'test'))
                self.log.info("deleting test data from splunk for test {0}".format(test['file']))
                splunk_sdk.delete_attack_data(instance_ip, str(self.config['splunk_admin_password']), splunk_rest_port, list(indexes))

        return result


    def load_file(self, file_path):
        """
        local_file function loads the yaml file and  convert it into a list
        :param file_path: path to the yaml file
        :return: file list
        """
        with open(file_path, 'r', encoding="utf-8") as stream:
            try:
                file = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                self.log.error(exc)
                sys.exit("ERROR: reading {0}".format(file_path))
        return file

    def get_instance_ip_and_port(self):
        """
        get_instance_ip_and_port function gets the IP and port of the splunk server.
        :return: instance IP and port
        """
        instance_ip = self.config['splunk_server_private_ip']
        splunk_rest_port = 8089

        return instance_ip, splunk_rest_port

