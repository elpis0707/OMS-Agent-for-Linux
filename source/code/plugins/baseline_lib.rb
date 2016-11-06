require 'json'
require 'securerandom' # SecureRandom.uuid 

require_relative 'oms_common'

module OMS
    class Baseline

        @@log = nil
        def self.log= (value)
	        @@log = value
        end

        # ------------------------------------------------------
        def self.transform_and_wrap(results, host, time)		
            if results == nil
                @@log.error "Baseline Assessment failed; Empty input"
                return nil, nil
            end

            if results["results"] == nil 
                @@log.error "Baseline Assessment failed; Invalid input:" + results.inspect
                return nil, nil
            end

            results["assessment_id"] = SecureRandom.uuid      
    
            asm_baseline_results = results["results"]
            scan_time = results["scan_time"]
            assessment_id = results["assessment_id"]

            baseline_blob = {
                "DataType"=>"SECURITY_BASELINE_BLOB", 
                "IPName"=>"Security",
                "DataItems"=>[
                ]
            }	

            asm_baseline_results.each do |asm_baseline_result|
                oms_baseline_result = self.transform_asm_2_oms(asm_baseline_result, scan_time, host, assessment_id)		
                baseline_blob["DataItems"].push(oms_baseline_result)
            end 

            baseline_summary_blob = self.calculate_summary(results, host, time)

            @@log.info "Baseline Summary: " + baseline_summary_blob.inspect	

            return baseline_blob, baseline_summary_blob
        end # self.transform_and_wrap
    
        # ------------------------------------------------------	   
        def self.calculate_summary(results, hostname, time)  
            asm_baseline_results = results["results"]
            assessment_id = results["assessment_id"]
            critical_failed_rules = 0;
            warning_failed_rules = 0;
            informational_failed_rules = 0;
            all_failed_rules = 0;
    
            asm_baseline_results.each do |asm_baseline_result|

                if asm_baseline_result["result"] == "PASS"  
                    next 
                end

                all_failed_rules += 1

                case asm_baseline_result["severity"]
                when "Critical", "Important"
                    critical_failed_rules += 1
                when "Warning"
                    warning_failed_rules += 1             
                else
                    informational_failed_rules += 1
                end                   
            end 

            percentage_of_passed_rules = ((asm_baseline_results.length - all_failed_rules) * 100.0 / asm_baseline_results.length).round
    
            baseline_summary_blob = {
                "DataType" => "SECURITY_BASELINE_SUMMARY_BLOB",
                "IPName" => "Security",
                "DataItems" => [
                    {
                        "Computer" => hostname,
                        "TotalAssessedRules" => asm_baseline_results.length,
                        "CriticalFailedRules" => critical_failed_rules,
                        "WarningFailedRules" => warning_failed_rules,
                        "InformationalFailedRules" => informational_failed_rules,
                        "PercentageOfPassedRules" => percentage_of_passed_rules,
                        "AssessmentId" => assessment_id,
                        "OSName" => "Linux"
                    }
                ] 
            }

            return baseline_summary_blob
        end # calculate_summary 

        # ------------------------------------------------------
        def self.transform_asm_2_oms(asm_baseline_result, scan_time, host, assessment_id)
            oms = {
                "TimeAnalyzed" => scan_time,
                "Computer" => host,

                "CceId"=> asm_baseline_result["cceid"],
                "Severity" => asm_baseline_result["severity"],
                "Name" => asm_baseline_result["description"],
                "AnalyzeResult" => asm_baseline_result["result"] == "PASS" ? "Passed" : "Failed",
                "AssessmentId" => assessment_id,
                "OSName" => "Linux",
                "RuleType" => "Command"
            }
            return oms		
        end # transform_asm_2_oms
    end # class
end # module
