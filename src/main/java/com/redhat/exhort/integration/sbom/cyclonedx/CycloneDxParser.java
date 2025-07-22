/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.redhat.exhort.integration.sbom.cyclonedx;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.cyclonedx.Version;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.parsers.JsonParser;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.ValidationMessage;
import com.redhat.exhort.api.PackageRef;
import com.redhat.exhort.config.ObjectMapperProducer;
import com.redhat.exhort.config.exception.CycloneDXValidationException;
import com.redhat.exhort.integration.sbom.SbomParser;
import com.redhat.exhort.model.DependencyTree;
import com.redhat.exhort.model.DirectDependency;

public class CycloneDxParser extends SbomParser {

  private static final ObjectMapper MAPPER = ObjectMapperProducer.newInstance();
  private static final Logger LOGGER = Logger.getLogger(CycloneDxParser.class);
  private static final JsonParser JSON_PARSER = new JsonParser();

  @Override
  public DependencyTree buildTree(InputStream input) {

    var treeBuilder = DependencyTree.builder();
    var bom = parseBom(input);
    Map<String, PackageRef> componentPurls = new HashMap<>();
    if (bom.getComponents() != null) {
      componentPurls.putAll(
          bom.getComponents().stream()
              .filter(c -> c.getBomRef() != null && c.getPurl() != null)
              .collect(Collectors.toMap(Component::getBomRef, c -> new PackageRef(c.getPurl()))));
    }

    Optional<Component> rootComponent = Optional.empty();
    if (bom.getMetadata() != null) {
      rootComponent = Optional.ofNullable(bom.getMetadata().getComponent());
    }

    PackageRef rootRef = null;
    if (rootComponent.isPresent()) {
      if (rootComponent.get().getPurl() != null) {
        rootRef = new PackageRef(rootComponent.get().getPurl());
      } else if (componentPurls.containsKey(rootComponent.get().getBomRef())) {
        rootRef = componentPurls.get(rootComponent.get().getBomRef());
      }
      if (rootRef == null) {
        rootRef =
            new PackageRef(
                String.format(
                    "pkg:generic/%s@%s",
                    rootComponent.get().getName(), rootComponent.get().getVersion()));
      }
    }
    var tree = treeBuilder.dependencies(buildDependencies(bom, componentPurls, rootRef)).build();
    return tree;
  }

  private Map<PackageRef, DirectDependency> buildDependencies(
      Bom bom, Map<String, PackageRef> componentPurls, PackageRef rootRef) {
    if (bom.getDependencies() == null || bom.getDependencies().isEmpty()) {
      return buildUnknownDependencies(componentPurls);
    }

    Map<PackageRef, Set<PackageRef>> dependencies = new HashMap<>();
    bom.getDependencies()
        .forEach(
            d -> {
              PackageRef ref = componentPurls.getOrDefault(d.getRef(), rootRef);
              Set<PackageRef> deps = new HashSet<>();
              if (d.getDependencies() != null) {
                d.getDependencies()
                    .forEach(
                        dep -> {
                          PackageRef depRef = componentPurls.get(dep.getRef());
                          if (depRef != null) {
                            deps.add(depRef);
                          }
                        });
              }
              dependencies.put(ref, deps);
            });

    addUnknownDependencies(dependencies, componentPurls);

    Set<PackageRef> directDeps;
    if (rootRef != null && dependencies.containsKey(rootRef)) {
      directDeps = new HashSet<>(dependencies.get(rootRef));
    } else {
      directDeps = new HashSet<>(dependencies.keySet());
      dependencies.values().forEach(directDeps::removeAll);
    }

    componentPurls.values().stream()
        .filter(Predicate.not(dependencies::containsKey))
        .forEach(directDeps::add);

    Map<PackageRef, DirectDependency> result = new HashMap<>();
    directDeps.forEach(
        directRef -> {
          Set<PackageRef> transitiveRefs = new HashSet<>();
          findTransitiveIterative(directRef, dependencies, transitiveRefs);
          result.put(
              directRef,
              DirectDependency.builder().ref(directRef).transitive(transitiveRefs).build());
        });

    return result;
  }

  private void addUnknownDependencies(
      Map<PackageRef, Set<PackageRef>> dependencies, Map<String, PackageRef> componentPurls) {
    Set<PackageRef> knownDeps = new HashSet<>(dependencies.keySet());
    dependencies.values().forEach(knownDeps::addAll);
    componentPurls.values().stream()
        .filter(Predicate.not(knownDeps::contains))
        .forEach(d -> dependencies.put(d, new HashSet<>()));
  }

  private void findTransitiveIterative(
      PackageRef startRef, Map<PackageRef, Set<PackageRef>> dependencies, Set<PackageRef> acc) {
    Set<PackageRef> toProcess = new HashSet<>();
    toProcess.add(startRef);

    while (!toProcess.isEmpty()) {
      PackageRef current = toProcess.iterator().next();
      toProcess.remove(current);

      Set<PackageRef> deps = dependencies.get(current);
      if (deps != null) {
        deps.stream()
            .filter(d -> !acc.contains(d))
            .forEach(
                d -> {
                  acc.add(d);
                  toProcess.add(d);
                });
      }
    }
  }

  private Map<PackageRef, DirectDependency> buildUnknownDependencies(
      Map<String, PackageRef> componentPurls) {
    Map<PackageRef, DirectDependency> deps = new HashMap<>();
    componentPurls
        .values()
        .forEach(
            v -> {
              if (deps.containsKey(v)) {
                LOGGER.debugf("Ignore duplicate key %s", v);
              }
              deps.put(v, DirectDependency.builder().ref(v).build());
            });
    return deps;
  }

  private Bom parseBom(InputStream input) {
    try {
      JsonNode node = MAPPER.readTree(input);
      var bom = MAPPER.treeToValue(node, Bom.class);
      var version = parseSchemaVersion(bom.getSpecVersion());
      var schema = JSON_PARSER.getJsonSchema(version, MAPPER);
      var errors = schema.validate(node);
      if (errors != null && !errors.isEmpty()) {
        throw new ParseException(
            errors.stream().map(ValidationMessage::getMessage).toList().toString());
      }
      return bom;
    } catch (ParseException e) {
      LOGGER.debug("CycloneDX Validation error: ", e);
      throw new CycloneDXValidationException(e);
    } catch (IOException e) {
      LOGGER.error("CycloneDX Validation error: ", e);
      throw new CycloneDXValidationException(e);
    }
  }

  private Version parseSchemaVersion(String version) throws ParseException {
    if (version == null) {
      throw new ParseException("Missing CycloneDX Spec Version");
    }
    return switch (version) {
      case "1.6" -> Version.VERSION_16;
      case "1.5" -> Version.VERSION_15;
      case "1.4" -> Version.VERSION_14;
      case "1.3" -> Version.VERSION_13;
      case "1.2" -> Version.VERSION_12;
      case "1.1" -> Version.VERSION_11;
      case "1.0" -> Version.VERSION_10;
      default -> throw new ParseException("Invalid Spec Version received");
    };
  }
}
